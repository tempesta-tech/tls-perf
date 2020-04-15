/**
 *		TLS handshakes benchmarking tool.
 *
 * Copyright (C) 2020 Tempesta Technologies, INC.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <execinfo.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <list>
#include <sstream>
#include <string>
#include <thread>

#include <openssl/ssl.h>
#include <openssl/err.h>

static const int DEFAULT_THREADS = 1;
static const int PEERS_SLOW_START = 10;
static const int DEFAULT_PEERS = 1;
static const char *DEFAULT_CIPHER = "ECDHE-ECDSA-AES128-GCM-SHA256";

struct {
	typedef std::chrono::time_point<std::chrono::steady_clock> __time_t;

	std::atomic<uint32_t>	total_tcp_connections;
	std::atomic<uint32_t>	tls_connections;
	std::atomic<uint32_t>	error_count;
	std::atomic<uint32_t>	epoch_start_tcp_connections;

	__time_t		start_time;
} stat __attribute__((aligned(L1DSZ))); // no split-locking

struct {
	int		n_peers;
	int		n_threads;
	uint32_t	ip;
	uint16_t	port;
	bool		debug;
	const char	*cipher;
} g_opt;

class Except : public std::exception {
private:
	static const size_t maxmsg = 256;
	std::string str_;

public:
	Except(const char* fmt, ...) noexcept
	{
		va_list ap;
		char msg[maxmsg];
		va_start(ap, fmt);
		vsnprintf(msg, maxmsg, fmt, ap);
		va_end(ap);
		str_ = msg;

		// Add system error code (errno).
		if (errno) {
			std::stringstream ss;
			ss << " (" << strerror(errno)
				<< ", errno=" << errno << ")";
			str_ += ss.str();
		}

		// Add OpenSSL error code if exists.
		unsigned long ossl_err = ERR_get_error();
		if (ossl_err) {
			char buf[256];
			str_ += std::string(": ")
				+ ERR_error_string(ossl_err, buf);
		}

		// Add call trace symbols.
		if (g_opt.debug)
			call_trace();
	}

	~Except() noexcept
	{}

	const char *
	what() const noexcept
	{
		return str_.c_str();
	}

private:
	void
	call_trace() noexcept
	{
		// Do not print more that BTRACE_CALLS_NUM calls in the trace.
		static const size_t BTRACE_CALLS_NUM	= 32;

		void *trace_addrs[BTRACE_CALLS_NUM];
		int n_addr = backtrace(trace_addrs,
				sizeof(trace_addrs) / sizeof(trace_addrs[0]));
		if (!n_addr)
			return;

		char **btrace = backtrace_symbols(trace_addrs, n_addr);
		if (!btrace)
			return;

		for (auto i = 0; i < n_addr; ++i)
			str_ += std::string("\n\t") + btrace[i];

		free(btrace);
	}
};

struct SocketHandler {
	virtual ~SocketHandler() {};
	virtual bool next_state() =0;

	int sd;
};

class IO {
private:
	static const size_t N_EVENTS = 128;
	static const size_t TO_MSEC = 5;

public:
	IO()
	{
		tls_ = SSL_CTX_new(TLS_client_method());

		// Limit to TLSv1.2 at the moment.
		SSL_CTX_set_min_proto_version(tls_, TLS1_2_VERSION);
		SSL_CTX_set_max_proto_version(tls_, TLS1_2_VERSION);

		// No session resumption.
		SSL_CTX_set_options(tls_, SSL_OP_NO_TICKET);

		// Use SSL_CTX_set_ciphersuites() for TLSv1.3.
		SSL_CTX_set_cipher_list(tls_, g_opt.cipher);

		if ((ed_ = epoll_create(1)) < 0)
			throw std::string("can't create epoll");
		memset(events_, 0, sizeof(events_));
	}

	~IO()
	{
		if (ed_)
			close(ed_);
	}

	void
	add(SocketHandler *sh)
	{
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLOUT | EPOLLERR,
			.data = { .ptr = sh }
		};

		if (epoll_ctl(ed_, EPOLL_CTL_ADD, sh->sd, &ev) < 0)
			throw Except("can't add socket to poller");
	}

	void
	del(SocketHandler *sh)
	{
		if (epoll_ctl(ed_, EPOLL_CTL_DEL, sh->sd, NULL) < 0)
			throw Except("can't delete socket from poller");
	}

	void
	wait()
	{
	retry:
		ev_count_ = epoll_wait(ed_, events_, N_EVENTS, TO_MSEC);
		if (ev_count_ < 0) {
			if (errno == EINTR)
				goto retry;
			throw Except("poller wait error");
		}
	}

	SocketHandler *
	next_sk() noexcept
	{
		if (ev_count_ <= 0)
			return NULL;
		return (SocketHandler *)events_[--ev_count_].data.ptr;
	}

	SSL *
	new_tls_ctx(SocketHandler *sh)
	{
		SSL *ctx = SSL_new(tls_);
		if (!ctx)
			throw Except("cannot clone TLS context");

		SSL_set_fd(ctx, sh->sd);

		return ctx;
	}

private:
	int		ed_;
	int		ev_count_;
	SSL_CTX		*tls_;
	struct epoll_event events_[N_EVENTS];
};

class Peer : public SocketHandler {
private:
	enum _states {
		STATE_TCP_CONNECT,
		STATE_TCP_CONNECTING,
		STATE_TLS_HANDSHAKING,
	};

private:
	IO			&io_;
	SSL			*tls_;
	enum _states		state_;
	struct sockaddr_in	addr_;
	bool			polled_;

public:
	Peer(IO &io) noexcept
		: io_(io), tls_(NULL)
		, state_(STATE_TCP_CONNECT), polled_(false)
	{
		sd = -1;
		::memset(&addr_, 0, sizeof(addr_));
		addr_.sin_family = AF_INET;
		addr_.sin_port = g_opt.port;
		addr_.sin_addr.s_addr = g_opt.ip;
	}

	virtual ~Peer()
	{
		disconnect();
	}

	bool
	next_state() final override
	{
		switch (state_) {
		case STATE_TCP_CONNECT:
			return tcp_connect();
		case STATE_TCP_CONNECTING:
			return tcp_connect_try_finish();
		case STATE_TLS_HANDSHAKING:
			tls_handshake();
			break;
		default:
			throw Except("bad next state %d", state_);
		}
		return false;
	}

private:
	void
	add_to_poll()
	{
		if (!polled_) {
			io_.add(this);
			polled_ = true;
		}
	}

	void
	del_from_poll()
	{
		if (polled_) {
			io_.del(this);
			polled_ = false;
		}
	}

	void
	tls_handshake()
	{
		state_ = STATE_TLS_HANDSHAKING;

		if (!tls_)
			tls_ = io_.new_tls_ctx(this);

		int r = SSL_connect(tls_);
		if (r == 1) {
			// Handshake completed.
			stat.tls_connections++;
			disconnect();
			tcp_connect();
			return;
		}

		switch (SSL_get_error(tls_, r)) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			add_to_poll();
			break;
		default:
			if (stat.tls_connections <= 0)
				throw Except("cannot establish even one TLS"
					     " connection");
			stat.error_count++;
			disconnect();
		}
	}

	bool
	tcp_connect_try_finish(int ret = -1)
	{
		if (ret == -1) {
			socklen_t len = 4;
			if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &ret, &len))
				throw Except("cannot get a socket connect()"
					     " status");
		}

		if (!ret) {
			// TCP connection established.
			stat.total_tcp_connections++;
			tls_handshake();
			return true;
		}

		// Some error on the socket.
		state_ = STATE_TCP_CONNECTING;
		if (errno != EINPROGRESS && errno != EAGAIN) {
			if (stat.total_tcp_connections <= 0)
				throw Except("cannot establish even one"
					     " TCP connection");
			disconnect();
			return false;
		}
		// Continue to wait on TCP handshake.
		add_to_poll();
		return false;
	}

	bool
	tcp_connect()
	{
		if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
			throw Except("cannot create a socket");

		fcntl(sd, F_SETFL, fcntl(sd, F_GETFL, 0) | O_NONBLOCK);

		int r = connect(sd, (struct sockaddr *)&addr_, sizeof(addr_));

		// On on localhost connect() can complete instantly
		// even on non-blocking sockets.
		return tcp_connect_try_finish(r);
	}

	void
	disconnect() noexcept
	{
		if (tls_) {
			// Make sure session is not kept in cache.
			// Calling SSL_free() without calling SSL_shutdown will
			// also remove the session from the session cache.
			SSL_free(tls_);
			tls_ = NULL;
		}
		if (sd >= 0) {
			try {
				del_from_poll();
			}
			catch (Except &e) {
				std::cerr << "ERROR disconnect: "
					<< e.what() << std::endl;
			}

			// Disable TIME-WAIT state, close immediately.
			struct linger sl = { .l_onoff = 1, .l_linger = 0 };
			setsockopt(sd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
			close(sd);

			sd = -1;
		}

		state_ = STATE_TCP_CONNECT;
		stat.tls_connections--;
	}
};

void
usage()
{
	std::cout << "\n"
		<< "./tls-perf [options] <ip> <port>\n"
		<< "  -h,--help    Print this help and exit.\n"
		<< "  -d,--debug   Run in debug mode.\n"
		<< "  -l <n>       Limit parallel connections for each thread"
		<< " (default: " << DEFAULT_PEERS << ").\n"
		<< "  -t <n>       Number of threads"
		<< " (default: " << DEFAULT_THREADS << ").\n"
		<< "  -c <cipher>  Force cipher choice (default: "
		<< DEFAULT_CIPHER << ").\n"
		<< "\n"
		<< "127.0.0.1:443 address is used by default.\n"
		<< "\n"
		<< "To list available ciphers run command:\n"
		<< "$ nmap --script ssl-enum-ciphers -p <PORT> <IP>\n"
		<< std::endl;
	exit(0);
}

static void
do_getopt(int argc, char *argv[])
{
	int c, i, o = 0;

	g_opt.n_peers = DEFAULT_PEERS;
	g_opt.n_threads = DEFAULT_THREADS;
	g_opt.port = htons(443);
	g_opt.ip = inet_addr("127.0.0.1");
	g_opt.cipher = DEFAULT_CIPHER;
	g_opt.debug = false;

	static struct option long_opts[] = {
		{"help", no_argument, NULL, 'h'},
		{"debug", no_argument, NULL, 'd'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "hl:c:dt:", long_opts, &o)) != -1) {
		switch (c) {
		case 0:
			break;
		case 'c':
			g_opt.cipher = optarg;
			break;
		case 'd':
			g_opt.debug = true;
			break;
		case 'l':
			g_opt.n_peers = atoi(optarg);
			break;
		case 't':
			g_opt.n_threads = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}

	if (optind != argc && optind + 2 != argc) {
		std::cerr << "\nERROR: need to specify both the address"
			<< " and port or use default values" << std::endl;
		usage();
	}

	i = optind;
	if (i < argc) {
		g_opt.ip = inet_addr(argv[i]);
		i++;
	}
	if (i < argc) {
		g_opt.port = htons(atoi(argv[i]));
		i++;
	}
}

void
statistics_update() noexcept
{
	using namespace std::chrono;

	auto total = &stat.total_tcp_connections;
	auto epoch = &stat.epoch_start_tcp_connections;
	auto delta = *total - *epoch;

	auto now(steady_clock::now());
	auto dt = duration_cast<milliseconds>(now - stat.start_time).count();

	std::cout << "Handshakes " << *total
		<< " [" << (float)(1000 * delta) / dt << " h/s], "
		<< stat.tls_connections << " Conn, "
		<< stat.error_count << " Err" << std::endl;

	epoch->store(*total);
	stat.start_time = now;
}

void
io_loop()
{
	int active_peers = 0;
	int new_peers = std::min(g_opt.n_peers, PEERS_SLOW_START);
	IO io;
	std::list<SocketHandler *> all_peers;

	while (1) {
		// We implement slow start of number of concurrent TCP
		// connections, so active_peers and peers dynamicly grow in
		// this loop.
		while (new_peers--) {
			Peer *p = new Peer(io);
			all_peers.push_back(p);
			++active_peers;
			if (p->next_state() && active_peers < g_opt.n_peers)
				++new_peers;
		}

		io.wait();
		while (auto p = io.next_sk())
			if (p->next_state() && active_peers < g_opt.n_peers)
				++new_peers;
	}

	// At the moment we never reach the point, but call the peer
	// destructor if we come to time limited benchmarking.
	for (auto p : all_peers)
		delete p;
}

int
main(int argc, char *argv[])
{
	do_getopt(argc, argv);

	SSL_library_init();
	SSL_load_error_strings();

	std::cout << "Use cipher '" << g_opt.cipher << "'" << std::endl;

	for (auto i = 0; i < g_opt.n_threads; ++i) {
		std::cout << "spawn thread " << (i + 1) << std::endl;
		std::thread([]() {
			try {
				io_loop();
			}
			catch (Except &e) {
				std::cerr << "ERROR: " << e.what() << std::endl;
				exit(1);
			}
		}).detach();
	}

	while (1) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
		statistics_update();
	}

	return 0;
}
