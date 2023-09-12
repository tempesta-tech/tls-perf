/**
 *		TLS handshakes benchmarking tool.
 *
 * Copyright (C) 2020-2023 Tempesta Technologies, INC.
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
#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <csignal>
#include <chrono>
#include <iostream>
#include <list>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/tls1.h>

static const int DEFAULT_THREADS = 1;
static const int DEFAULT_PEERS = 1;
static const int PEERS_SLOW_START = 10;
static const int LATENCY_N = 1024;

// Dump shared keys for Wireshark analysis
static BIO *bio_keylog;
void
keylog(const SSL *tls, const char *line)
{
	// There might be concurrent writers to the keylog file, ensure
	// that the given line is written at once.
	if (bio_keylog) {
		BIO_printf(bio_keylog, "%s\n", line);
		(void)(BIO_flush(bio_keylog));
	}
}

struct {
	int			n_peers;
	int			n_threads;
	size_t			n_hs;
	int			timeout;
	uint16_t		port;
	bool			debug;
	bool			quiet;
	int			tls_vers;
	int			use_tickets;
	int			adv_tickets;
	const char		*cipher;
	const char		*curve;
	const char		*keylogfile;
	const char		*sni;
	struct sockaddr_in6	ip;
} g_opt;

struct DbgStream {
	template<typename T>
	const DbgStream &
	operator<<(const T &v) const noexcept
	{
		if (g_opt.debug)
			std::cout << v;
		return *this;
	}

	const DbgStream &
	operator<<(std::ostream &(*manip)(std::ostream &)) const noexcept
	{
		if (g_opt.debug)
			manip(std::cout);
		return *this;
	}
} dbg;

struct {
	typedef std::chrono::time_point<std::chrono::steady_clock> __time_t;

	std::atomic<uint64_t>	tot_tls_handshakes;
	std::atomic<int32_t>	tcp_handshakes;
	std::atomic<int32_t>	tcp_connections;
	std::atomic<int32_t>	tls_connections;
	std::atomic<int32_t>	tls_handshakes;
	std::atomic<int32_t>	error_count;
	int32_t			__no_false_sharing[9];

	__time_t		stat_time;

	int32_t			measures;
	int32_t			max_hs;
	int32_t			min_hs;
	int32_t			avg_hs;
	std::vector<int32_t>	hs_history;

	void
	start_count()
	{
		stat_time = std::chrono::steady_clock::now();
	}
} stat __attribute__((aligned(L1DSZ))); // no split-locking

static struct {
	std::mutex			lock;
	std::vector<double>		stat;
	double				acc_lat;
} g_lat_stat;

class LatencyStat {
public:
	LatencyStat() noexcept
		: i_(0), di_(1), stat_({0})
	{}

	void
	update(double dt) noexcept
	{
		if (!dt) {
			dbg << "Bad zero latency" << std::endl;
			return;
		}
		stat_[i_] = dt;

		i_ += di_;
		// Write statistics in ring buffer fashion, but mix later
		// results with earlier instead of just rewriting them.
		if (i_ >= LATENCY_N) {
			i_ = 0;
			if (++di_ > LATENCY_N / 4)
				di_ = 1;
		}
	}

	void
	dump() noexcept
	{
		std::lock_guard<std::mutex> _(g_lat_stat.lock);
		for (auto l : stat_) {
			if (!l)
				break;
			g_lat_stat.stat.push_back(l);
			g_lat_stat.acc_lat += l;
		}
	}

private:
	unsigned int				i_;
	unsigned int				di_;
	std::array<double, LATENCY_N>		stat_;
};

static thread_local LatencyStat lat_stat __attribute__((aligned(L1DSZ)));

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
	}

	~Except() noexcept
	{}

	const char *
	what() const noexcept
	{
		return str_.c_str();
	}
};

struct SocketHandler {
	virtual ~SocketHandler() {};
	virtual bool next_state() =0;
	virtual SSL_SESSION* get_session() = 0;

	int sd;
};

class IO {
private:
	static const size_t N_EVENTS = 128;
	static const size_t TO_MSEC = 5;

private:
	int			ed_;
	int			ev_count_;
	SSL_CTX			*tls_ctx_;
	struct epoll_event	events_[N_EVENTS];
	std::list<SocketHandler *> reconnect_q_;
	std::list<SocketHandler *> backlog_;

public:
	IO()
		: ed_(-1), ev_count_(0), tls_ctx_(NULL)
	{
		tls_ctx_ = SSL_CTX_new(TLS_client_method());

		// Allow only TLS 1.2 and 1.3, and chose only those user has
		// requested.
		if (g_opt.tls_vers != TLS_ANY_VERSION) {
			SSL_CTX_set_min_proto_version(tls_ctx_, g_opt.tls_vers);
			SSL_CTX_set_max_proto_version(tls_ctx_, g_opt.tls_vers);
		} else {
			SSL_CTX_set_min_proto_version(tls_ctx_, TLS1_2_VERSION);
			SSL_CTX_set_max_proto_version(tls_ctx_, TLS1_3_VERSION);
		}

		// Session resumption.
		if (!g_opt.use_tickets) {
			unsigned int mode = SSL_SESS_CACHE_OFF
					  | SSL_SESS_CACHE_NO_INTERNAL;
			if (!g_opt.adv_tickets)
				SSL_CTX_set_options(tls_ctx_, SSL_OP_NO_TICKET);
			SSL_CTX_set_session_cache_mode(tls_ctx_, mode);
		}
		else {
			unsigned int mode = SSL_SESS_CACHE_CLIENT
					  | SSL_SESS_CACHE_NO_AUTO_CLEAR;
			SSL_CTX_set_session_cache_mode(tls_ctx_, mode);
		}

		if (g_opt.cipher) {
			if (g_opt.tls_vers == TLS1_3_VERSION
			    || g_opt.tls_vers == TLS_ANY_VERSION)
				if (!SSL_CTX_set_ciphersuites(tls_ctx_,
							      g_opt.cipher))
					throw Except("cannot set cipher");
			if (g_opt.tls_vers == TLS1_2_VERSION
			    || g_opt.tls_vers == TLS_ANY_VERSION)
				if (!SSL_CTX_set_cipher_list(tls_ctx_,
							     g_opt.cipher))
					throw Except("cannot set cipher");
		}
		if (g_opt.curve)
			if (!SSL_CTX_set1_groups_list(tls_ctx_, g_opt.curve))
				throw Except("cannot set elliptic curve");
		SSL_CTX_set_verify(tls_ctx_, SSL_VERIFY_NONE, NULL);
		if (g_opt.keylogfile)
			SSL_CTX_set_keylog_callback(tls_ctx_, keylog);

		if ((ed_ = epoll_create(1)) < 0)
			throw Except("can't create epoll");
		memset(events_, 0, sizeof(events_));
	}

	~IO()
	{
		if (ed_ > -1)
			close(ed_);
		reconnect_q_.clear();
		SSL_CTX_set_keylog_callback(tls_ctx_, nullptr);
		if (tls_ctx_)
			SSL_CTX_free(tls_ctx_);
	}

	void
	add(SocketHandler *sh, int events)
	{
		struct epoll_event ev = {
			.events = events | EPOLLONESHOT,
			.data = { .ptr = sh }
		};

		if (epoll_ctl(ed_, EPOLL_CTL_MOD, sh->sd, &ev) < 0) {
			if (errno == ENOENT &&
			    epoll_ctl(ed_, EPOLL_CTL_ADD, sh->sd, &ev) < 0)
			{
				throw Except("can't add socket to poller");
			}
		}
	}

	void
	del(SocketHandler *sh)
	{
		if (epoll_ctl(ed_, EPOLL_CTL_DEL, sh->sd, NULL) < 0)
			throw Except("can't delete socket from poller");
	}

	void
	queue_reconnect(SocketHandler *sh) noexcept
	{
		reconnect_q_.push_back(sh);
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
		if (ev_count_)
			return (SocketHandler *)events_[--ev_count_].data.ptr;
		return NULL;
	}

	void
	backlog() noexcept
	{
		backlog_.swap(reconnect_q_);
	}

	SocketHandler *
	next_backlog() noexcept
	{
		if (backlog_.empty())
			return NULL;

		SocketHandler *sh = backlog_.front();
		backlog_.pop_front();
		return sh;
	}

	SSL *
	new_tls_ctx(SocketHandler *sh)
	{
		SSL *ctx = SSL_new(tls_ctx_);
		if (!ctx)
			throw Except("cannot clone TLS context");

		SSL_set_fd(ctx, sh->sd);
		BIO_set_tcp_ndelay(sh->sd, true);
		if (g_opt.use_tickets) {
			auto sess = sh->get_session();
			if (sess)
				SSL_set_session(ctx, sess);
		}

		if(g_opt.sni)
			SSL_set_tlsext_host_name(ctx, g_opt.sni);

		return ctx;
	}
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
	int			id_;
	SSL			*tls_;
	SSL_SESSION		*sess_;
	std::chrono::time_point<std::chrono::steady_clock> ts_;
	enum _states		state_;

public:
	Peer(IO &io, int id) noexcept
		: io_(io), id_(id), tls_(NULL), sess_(NULL)
		, state_(STATE_TCP_CONNECT)
	{
		sd = -1;
		dbg_status("created");
	}

	virtual ~Peer()
	{
		disconnect();
		if (sess_)
			SSL_SESSION_free(sess_);
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
			return tls_handshake();
		default:
			throw Except("bad next state %d", state_);
		}
		return false;
	}

	SSL_SESSION*
	get_session()
	{
		return sess_;
	}

private:
	void
	poll_for_read()
	{
		io_.add(this, EPOLLIN | EPOLLERR);
	}

	void
	poll_for_write()
	{
		io_.add(this, EPOLLOUT | EPOLLERR);
	}

	void
	del_from_poll()
	{
		io_.del(this);
	}

	void
	dbg_status(const char *msg) noexcept
	{
		if (g_opt.debug)
			dbg << "peer " << id_ << " " << msg << std::endl;
	}

	bool
	tls_handshake()
	{
		using namespace std::chrono;

		state_ = STATE_TLS_HANDSHAKING;

		if (!tls_) {
			tls_ = io_.new_tls_ctx(this);
			stat.tls_handshakes++;
			ts_ = steady_clock::now();
		}

		int r = SSL_connect(tls_);
		if (r == 1) {
			auto t1(steady_clock::now());
			const duration<double, std::milli> lat = t1 - ts_;
			lat_stat.update(lat.count());

			dbg_status("has completed TLS handshake");
			stat.tls_handshakes--;
			stat.tls_connections++;
			stat.tot_tls_handshakes++;
			disconnect();
			stat.tcp_connections--;
			io_.queue_reconnect(this);
			return true;
		}

		switch (SSL_get_error(tls_, r)) {
		case SSL_ERROR_WANT_READ:
			poll_for_read();
			break;
		case SSL_ERROR_WANT_WRITE:
			poll_for_write();
			break;
		default:
			if (!stat.tot_tls_handshakes)
				throw Except("cannot establish even one TLS"
					     " connection");
			stat.tls_handshakes--;
			stat.error_count++;
			disconnect();
			stat.tcp_connections--;
		}
		return false;
	}

	bool
	handle_established_tcp_conn()
	{
		// del_from_poll(); // not needed as we're using EPOLLONESHOT
		dbg_status("has established TCP connection");
		stat.tcp_handshakes--;
		stat.tcp_connections++;
		return tls_handshake();
	}

	void
	handle_connect_error(int err)
	{
		if (err == EINPROGRESS || err == EAGAIN) {
			errno = 0;

			// Continue to wait on the TCP handshake.
			//add_to_poll();
			poll_for_write();

			return;
		}

		if (!stat.tcp_connections)
			throw Except("cannot establish even one TCP connection");

		errno = 0;
		stat.tcp_handshakes--;
		disconnect();
	}

	bool
	tcp_connect_try_finish()
	{
		int ret = 0;
		socklen_t len = 4;

		if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &ret, &len))
			throw Except("cannot get a socket connect() status");

		if (!ret)
			return handle_established_tcp_conn();

		handle_connect_error(ret);
		return false;
	}

	bool
	tcp_connect()
	{
		sd = socket(g_opt.ip.sin6_family, SOCK_STREAM, IPPROTO_TCP);
		if (sd < 0)
			throw Except("cannot create a socket");

		fcntl(sd, F_SETFL, fcntl(sd, F_GETFL, 0) | O_NONBLOCK);

		int sz = (g_opt.ip.sin6_family == AF_INET) ? sizeof(sockaddr_in)
							   : sizeof(sockaddr_in6);
		int r = connect(sd, (struct sockaddr *)&g_opt.ip, sz);

		stat.tcp_handshakes++;
		state_ = STATE_TCP_CONNECTING;

		// On on localhost connect() can complete instantly
		// even on non-blocking sockets (e.g. Tempesta FW case).
		if (!r)
			return handle_established_tcp_conn();

		handle_connect_error(errno);
		return false;
	}

	void
	disconnect() noexcept
	{
		if (tls_) {
			// SSL_shutdown() marks the session as established and
			// saves it into session cache. Ignore it and just clean
			// the session if resumed sessions are unwanted.
			// Even SSL_CTX_set_session_cache_mode() doesn't help to
			// restrict session cache usage.
			if (g_opt.use_tickets) {
				auto old_sess = sess_;
				SSL_shutdown(tls_);
				sess_ = SSL_get1_session(tls_);
				SSL_SESSION_free(old_sess);
			}
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
			// This leads to connection terminations with RST and
			// on high traffic valume you may see large number of
			// ESTABLISHED connections, which will be terminated by
			// the OS on timeout.
			// https://github.com/tempesta-tech/tempesta/issues/1432
			struct linger sl = { .l_onoff = 1, .l_linger = 0 };
			setsockopt(sd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
			close(sd);

			sd = -1;
		}

		state_ = STATE_TCP_CONNECT;
	}
};

void
usage() noexcept
{
	std::cout << "\n"
		<< "./tls-perf [options] <ip> <port>\n"
		<< "  -h,--help            Print this help and exit\n"
		<< "  -d,--debug           Run in debug mode\n"
		<< "  -q,--quiet           Show less statistics in the run time\n"
		<< "  -l <N>               Limit parallel connections for each thread"
		<< " (default: " << DEFAULT_PEERS << ")\n"
		<< "  -n <N>               Total number of handshakes to establish\n"
		<< "  -t <N>               Number of threads"
		<< " (default: " << DEFAULT_THREADS << ").\n"
		<< "  -T,--to              Duration of the test (in seconds)\n"
		<< "  -c <cipher>          Force cipher choice\n"
		<< "                       (use `openssl ciphers` to list available"
					   " cipher suites),\n"
		<< "  -C <curve>           Force specific curve for elliptic curve"
					   " algorithms (use\n"
		<< "                       `openssl ecparam -list_curves`"
					   " to list available curves).\n"
		<< "  -V,--tls <version>   Set TLS version for handshake:\n"
		<< "                       '1.2', '1.3' or 'any' for both (default: '1.2')\n"
		<< "  -K,--tickets <mode>  Process TLS Session tickets and session"
					   " resumption,\n"
		<< "                       'on', 'off' or 'advertise', "
		<< "(default: 'off')\n"
		<< "  -F,--keylogfile <f>  File to dump keys for traffic analysers\n"
		<< "  -s,--sni <servernameindicator>  SNI to use for the given <ip>"
		<< "\n\n"
		<< "127.0.0.1:443 address is used by default.\n"
		<< "\n"
		<< "To list available ciphers on a remote peer use:\n"
		<< "$ nmap --script ssl-enum-ciphers -p <PORT> <IP>\n"
		<< std::endl;
	exit(0);
}

static int
parse_ipv4(const char *addr, const char *port)
{
	memset(&g_opt.ip, 0, sizeof(g_opt.ip));

	sockaddr_in *ipv4 = (sockaddr_in *)&g_opt.ip;
	if (inet_pton(AF_INET, addr, &ipv4->sin_addr) != 1)
		return -EINVAL;

	ipv4->sin_family = AF_INET;
	ipv4->sin_port = htons(atoi(port));

	return 0;
}

static int
parse_ipv6(const char *addr, const char *port)
{
	memset(&g_opt.ip, 0, sizeof(g_opt.ip));

	if (inet_pton(AF_INET6, addr, &g_opt.ip.sin6_addr) != 1)
		return -EINVAL;

	g_opt.ip.sin6_family = AF_INET6;
	g_opt.ip.sin6_port = htons(atoi(port));

	return 0;
}

static int
do_getopt(int argc, char *argv[]) noexcept
{
	int c, o = 0;

	g_opt.n_peers = DEFAULT_PEERS;
	g_opt.n_threads = DEFAULT_THREADS;
	g_opt.n_hs = ULONG_MAX; // infinite, in practice
	g_opt.cipher = NULL;
	g_opt.curve = NULL;
	g_opt.keylogfile = NULL;
	g_opt.sni = NULL;
	g_opt.debug = false;
	g_opt.timeout = 0;
	g_opt.tls_vers = TLS1_2_VERSION;
	g_opt.use_tickets = false;
	g_opt.adv_tickets = false;

	static struct option long_opts[] = {
		{"help", no_argument, NULL, 'h'},
		{"debug", no_argument, NULL, 'd'},
		{"quiet", no_argument, NULL, 'q'},
		{"to", no_argument, NULL, 'T'},
		{"tls", required_argument, NULL, 'V'},
		{"tickets", required_argument, NULL, 'K'},
		{"keylogfile", required_argument, NULL, 'F'},
		{"sni", required_argument, NULL, 's'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "hl:c:C:dqt:n:T:", long_opts, &o))
		!= -1)
	{
		switch (c) {
		case 0:
			break;
		case 'c':
			g_opt.cipher = optarg;
			break;
		case 'C':
			g_opt.curve = optarg;
			break;
		case 'd':
			g_opt.debug = true;
			break;
		case 'q':
			g_opt.quiet = true;
			break;
		case 'l':
			g_opt.n_peers = atoi(optarg);
			break;
		case 't':
			g_opt.n_threads = atoi(optarg);
			if (g_opt.n_threads > 512) {
				std::cerr << "ERROR: too many threads requested"
					<< std::endl;
				exit(2);
			}
			break;
		case 'n':
			g_opt.n_hs = atoi(optarg);
			break;
		case 'T':
			g_opt.timeout = atoi(optarg);
			break;
		case 'V':
			if (!strncmp(optarg, "1.2", 4)) {
				g_opt.tls_vers = TLS1_2_VERSION;
			} else if (!strncmp(optarg, "1.3", 4)) {
				g_opt.tls_vers = TLS1_3_VERSION;
			} else if (!strncmp(optarg, "any", 4)) {
				g_opt.tls_vers = TLS_ANY_VERSION;
			}else {
				std::cout << "Unknown TLS version, fallback to"
					     " 1.2\n" << std::endl;
				g_opt.tls_vers = TLS1_2_VERSION;
			}
			break;
		case 'K':
			if (!strncmp(optarg, "on", 3)) {
				g_opt.use_tickets = true;
			} else if (!strncmp(optarg, "off", 4)) {
				g_opt.use_tickets = false;
			} else if (!strncmp(optarg, "advertise", 10)) {
				g_opt.use_tickets = false;
				g_opt.adv_tickets = true;
			}else {
				std::cout << "Unknown TLS version, fallback to"
					     " 1.2\n" << std::endl;
				g_opt.tls_vers = TLS1_2_VERSION;
			}
			break;
		case 'F':
			g_opt.keylogfile = optarg;
			break;
		case 's':
			g_opt.sni = optarg;
			break;
		case 'h':
		default:
			usage();
			return 1;
		}
	}
	if (g_opt.keylogfile) {
		// Don't drop previously saved keys
		bio_keylog = BIO_new_file(g_opt.keylogfile, "a");
		if (!bio_keylog) {
			std::cerr << "Error writing keylog file '"
				  << g_opt.keylogfile << "'" << std::endl;
			return -ENOENT;
		}
	}

	if (optind != argc && optind + 2 != argc) {
		std::cerr << "\nERROR: either 0 or 2 arguments are allowed: "
			  << "none for defaults or address and port."
			  << std::endl;
		usage();
		return -EINVAL;
	}
	if (optind >= argc) {
		parse_ipv4("127.0.0.1", "443");
		return 0;
	}
	const char *addr_str = argv[optind];
	const char *port_str = argv[++optind];
	if (parse_ipv4(addr_str, port_str) && parse_ipv6(addr_str, port_str)) {
		std::cerr << "ERROR: can't parse ip address from string '"
			  << addr_str << "'" << std::endl;
		return -EINVAL;
	}
	return 0;
}

void
print_settings()
{
	char str[INET6_ADDRSTRLEN] = {};
	void *addr = g_opt.ip.sin6_family == AF_INET
			? (void *)&((sockaddr_in *)&g_opt.ip)->sin_addr
			: (void *)&g_opt.ip.sin6_addr;

	inet_ntop(g_opt.ip.sin6_family, addr, str, INET6_ADDRSTRLEN);
	std::cout << "Running TLS benchmark with following settings:\n"
		  << "Host:        " << str << " : "
		  << ntohs(g_opt.ip.sin6_port) << "\n"
		  << "TLS version: ";
	if (g_opt.tls_vers == TLS1_2_VERSION)
		std::cout << "1.2\n";
	else if (g_opt.tls_vers == TLS1_3_VERSION)
		std::cout << "1.3\n";
	else
		std::cout << "Any of 1.2 or 1.3\n";
	std::cout << "Cipher:      " << (g_opt.cipher ? : "default") << "\n"
		  << "TLS tickets: " << (g_opt.use_tickets
					 ? "on\n"
					 : !g_opt.adv_tickets ? "off\n"
							      : "advertise\n")
		  << "Duration:    " << g_opt.timeout << "\n"
		  << std::endl;
}

std::atomic<bool> finish(false), start_stats(false);

void
sig_handler(int signum) noexcept
{
	finish = true;
}

void
update_limits() noexcept
{
	struct rlimit open_file_limit = {};
	// Set limit for all the peer sockets + epoll socket for
	// each thread + standard IO.
	rlim_t req_fd_n = (g_opt.n_peers + 4) * g_opt.n_threads;

	getrlimit(RLIMIT_NOFILE, &open_file_limit);
	if (open_file_limit.rlim_cur > req_fd_n)
		return;

	if (!g_opt.quiet)
		std::cout << "set open files limit to " << req_fd_n << std::endl;
	open_file_limit.rlim_cur = req_fd_n;
	if (setrlimit(RLIMIT_NOFILE, &open_file_limit)) {
		g_opt.n_peers = open_file_limit.rlim_cur / (g_opt.n_threads + 4);
		std::cerr << "WARNING: required " << req_fd_n
			<< " (peers_number * threads_number), but setrlimit(2)"
			   " fails for this rlimit. Try to run as root or"
			   " decrease the numbers. Continue with "
			<< g_opt.n_peers << " peers" << std::endl;
		if (!g_opt.n_peers) {
			std::cerr << "ERROR: cannot run with no peers"
				<< std::endl;
			exit(3);
		}
	}
}

void
statistics_update() noexcept
{
	using namespace std::chrono;

	auto tls_conns = stat.tls_connections.load();

	auto now(steady_clock::now());
	auto dt = duration_cast<milliseconds>(now - stat.stat_time).count();

	stat.stat_time = now;
	stat.tls_connections -= tls_conns;

	int32_t curr_hs = (size_t)(1000 * tls_conns) / dt;
	if (!g_opt.quiet)
		std::cout << "TLS hs in progress " << stat.tls_handshakes
			<< " [" << curr_hs << " h/s],"
			<< " TCP open conns " << stat.tcp_connections
			<< " [" << stat.tcp_handshakes << " hs in progress],"
			<< " Errors " << stat.error_count << std::endl;

	if (!start_stats)
		return;

	stat.measures++;
	if (stat.max_hs < curr_hs)
		stat.max_hs = curr_hs;
	if (curr_hs && (stat.min_hs > curr_hs || !stat.min_hs))
		stat.min_hs = curr_hs;
	stat.avg_hs = (stat.avg_hs * (stat.measures - 1) + curr_hs)
			/ stat.measures;
	if (stat.hs_history.size() == 3600)
		std::cerr << "WARNING: benchmark is running for too long"
			<< " last history won't be stored" << std::endl;
	if (stat.hs_history.size() <= 3600)
		stat.hs_history.push_back(curr_hs);
}

void
statistics_dump() noexcept
{
	auto hsz = stat.hs_history.size();
	auto lsz = g_lat_stat.stat.size();

	if (!start_stats || hsz < 1 || lsz < 1) {
		std::cerr << "ERROR: not enough statistics collected"
			<< std::endl;
		return;
	}

	// Do this only once at the end of program, so sorting isn't a big deal.
	std::sort(stat.hs_history.begin(), stat.hs_history.end(),
		  std::greater<int32_t>());
	std::sort(g_lat_stat.stat.begin(), g_lat_stat.stat.end(),
		  std::less<int32_t>());

	std::cout << "========================================" << std::endl;
	std::cout << " TOTAL:           SECONDS " << stat.measures
		<< "; HANDSHAKES " << stat.tot_tls_handshakes << std::endl; 
	std::cout << " HANDSHAKES/sec: "
		<< " MAX " << stat.max_hs
		<< "; AVG " << stat.avg_hs
		// 95% handshakes are faster than this number.
		<< "; 95P " << stat.hs_history[hsz * 95 / 100]
		<< "; MIN " << stat.min_hs << std::endl;

	std::cout << " LATENCY (ms):   "
		<< " MIN " << g_lat_stat.stat.front()
		<< "; AVG " << g_lat_stat.acc_lat / lsz
		// 95% latencies are smaller than this one.
		<< "; 95P " << g_lat_stat.stat[lsz * 95 / 100]
		<< "; MAX " << g_lat_stat.stat.back() << std::endl;
}

bool
end_of_work() noexcept
{
	// We can make bit more handshakes than was specified by a user -
	// not a big deal.
	return finish || stat.tot_tls_handshakes >= g_opt.n_hs;
}

void
io_loop()
{
	int active_peers = 0;
	int new_peers = std::min(g_opt.n_peers, PEERS_SLOW_START);
	IO io;
	std::list<SocketHandler *> all_peers;

	while (!end_of_work()) {
		// We implement slow start of number of concurrent TCP
		// connections, so active_peers and peers dynamically grow in
		// this loop.
		for ( ; active_peers < g_opt.n_peers && new_peers; --new_peers)
		{
			Peer *p = new Peer(io, active_peers++);
			all_peers.push_back(p);

			if (p->next_state()
			    && active_peers + new_peers < g_opt.n_peers)
				++new_peers;
		}

		io.wait();
		while (auto p = io.next_sk()) {
			if (p->next_state()
			    && active_peers + new_peers < g_opt.n_peers)
				++new_peers;
		}

		// Process disconnected sockets from the backlog.
		io.backlog();
		while (!finish) {
			auto p = io.next_backlog();
			if (!p)
				break;
			if (p->next_state()
			    && active_peers + new_peers < g_opt.n_peers)
				++new_peers;
		}

		if (active_peers == g_opt.n_peers && !start_stats) {
			start_stats = true;
			std::cout << "( All peers are active, start to"
				  << " gather statistics )"
				  << std::endl;
		}
	}

	for (auto p : all_peers)
		delete p;
}

int
main(int argc, char *argv[])
{
	using namespace std::chrono;
	int r;

	if ((r = do_getopt(argc, argv))) {
		BIO_free_all(bio_keylog);
		return r;
	}
	if (!g_opt.quiet)
		print_settings();
	update_limits();

	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);

	SSL_library_init();
	SSL_load_error_strings();

	std::vector<std::thread> thr(g_opt.n_threads);
	for (auto i = 0; i < g_opt.n_threads; ++i) {
		dbg << "spawn thread " << (i + 1) << std::endl;
		thr[i] = std::thread([]() {
			try {
				io_loop();
			}
			catch (Except &e) {
				std::cerr << "ERROR: " << e.what() << std::endl;
				exit(1);
			}

			lat_stat.dump();
		});
	}

	auto start_t(steady_clock::now());
	stat.start_count();
	while (!end_of_work()) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
		statistics_update();

		auto now(steady_clock::now());
		auto dt = duration_cast<seconds>(now - start_t).count();
		if (g_opt.timeout && g_opt.timeout <= dt)
			finish = true;
	}

	for (auto &t : thr)
		t.join();

	statistics_dump();
	BIO_free_all(bio_keylog);

	return 0;
}
