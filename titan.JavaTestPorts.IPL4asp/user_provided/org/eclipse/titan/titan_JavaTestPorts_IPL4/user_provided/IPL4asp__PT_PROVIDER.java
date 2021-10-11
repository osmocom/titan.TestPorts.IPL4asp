package org.eclipse.titan.titan_JavaTestPorts_IPL4.user_provided;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLContext;

import org.eclipse.titan.runtime.core.AdditionalFunctions;
import org.eclipse.titan.runtime.core.Base_Template.template_sel;
import org.eclipse.titan.runtime.core.Optional;
import org.eclipse.titan.runtime.core.TTCN_Buffer;
import org.eclipse.titan.runtime.core.TTCN_Logger;
import org.eclipse.titan.runtime.core.TTCN_Logger.Severity;
import org.eclipse.titan.runtime.core.TTCN_Snapshot;
import org.eclipse.titan.runtime.core.TitanCharString;
import org.eclipse.titan.runtime.core.TitanInteger;
import org.eclipse.titan.runtime.core.TitanNull_Type;
import org.eclipse.titan.runtime.core.TitanOctetString;
import org.eclipse.titan.runtime.core.TitanPort;
import org.eclipse.titan.runtime.core.TtcnError;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.ASP__ConnId__ReadyToRelease;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.ASP__Event;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.ASP__RecvFrom;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.ASP__SendTo;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.IPL4__IPAddressType;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.IPL4__Param;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.IPL4__ParamResult;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.MTU__discover;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.Option;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.OptionList;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.SSL__proto__support;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.ConnectionClosedEvent;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.Extended__Result;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.PortError;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.ProtoTuple;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.Result;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.SctpTuple;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.SslTuple;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.TcpTuple;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.UdpTuple;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.f__getMsgLen;

public abstract class IPL4asp__PT_PROVIDER extends TitanPort {

	private boolean USE_IPV6 = false;
	private boolean USE_SCTP = false;
	private boolean IPL4_USE_SSL = false;
	private boolean USE_IPL4_EIN_SCTP = false;

	private static final int AF_INET = 2;
	private static final int AF_INET6 = 10;

	private static final int RECV_MAX_LEN = 65535;
	private static final int ADDR_LEN_MAX = 64;
	private static final int N_RECENTLY_CLOSED = 10;
	private static final int SOCK_LIST_SIZE_MIN = 16;
	private static final int IPL4_COOKIE_SECRET_LENGTH = 16;

	private static final int SO_MAX_CONN = 50;

	private static final String IPL4_IPV4_ANY_ADDR = "0.0.0.0";
	private static final String IPL4_IPV6_ANY_ADDR = "::";

	private InetSocketAddress sockAddr;

	private boolean debugAllowed;
	private boolean alreadyComplainedAboutMsgLen;
	private boolean mapped;

	private int sockListSize;
	private int sockListCnt;

	private String defaultLocHost;
	private int defaultLocPort;
	private String defaultRemHost;
	private int defaultRemPort;
	private int default_mode;
	private int default_proto;

	private boolean connId_release_confirmed;

	private int backlog;

	private boolean pureNonBlocking;
	private boolean send_extended_result;
	private double poll_timeout;
	private int max_num_of_poll;
	private GlobalConnOpts globalConnOpts;
	private int lonely_conn_id;
	private int lazy_conn_id_level;

	private int sctp_PMTU_size;
	private boolean broadcast;
	private boolean ssl_cert_per_conn;

	private Map<Integer, SockDesc> sockList;
	private int dontCloseConnectionId;
	private int closingPeerLen;

	private f__getMsgLen defaultGetMsgLen;
	private f__getMsgLen defaultGetMsgLen_forConnClosedEvent;
	private Socket__API__Definitions.ro__integer defaultMsgLenArgs;
	private Socket__API__Definitions.ro__integer defaultMsgLenArgs_forConnClosedEvent;

	public IPDiscConfig ipDiscConfig;
	public IPAddrLease ipAddrLease;

	private boolean ssl_verify_certificate;     // verify other part's certificate or not
	private boolean ssl_initialized;            // whether SSL already initialized or not
	private boolean ssl_use_session_resumption; // use SSL sessions or not
	private int ssl_reconnect_attempts;// maximum reconnect attempts, by default 5 (used only if pureNonBlocking is NOT used)
	private int ssl_reconnect_delay; // delay between reconnect attempts, by default 1 (used only if pureNonBlocking is NOT used)

	private String ssl_key_file;              // private key file
	private String ssl_certificate_file;      // own certificate file
	private String ssl_trustedCAlist_file;    // trusted CA list file
	private String ssl_cipher_list;           // ssl_cipher list restriction to apply
	private String ssl_password;              // password to decode the private key
	private String psk_identity;
	private String psk_identity_hint;
	private String psk_key;

	public static enum SSL_STATES {
		STATE_DONT_RECEIVE, STATE_WAIT_FOR_RECEIVE_CALLBACK, STATE_BLOCK_FOR_SENDING, STATE_DONT_CLOSE, STATE_NORMAL,
		STATE_CONNECTING, STATE_HANDSHAKING
	};

	public static enum SSL_HANDSHAKE_RESULT {
		SUCCESS, FAIL, WANT_READ, WANT_WRITE
	}

	public static enum SSL_TLS_Type {
		NONE, CLIENT, SERVER
	}

	public static enum SockType {
		IPL4asp_UDP,
		// IPL4asp_UDP_LIGHT,
		IPL4asp_TCP_LISTEN, IPL4asp_TCP, IPL4asp_SCTP_LISTEN, IPL4asp_SCTP
	}

	public IPL4asp__PT_PROVIDER(String port_name) {
		super(port_name);
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.IPL4asp__PT_PROVIDER: enter");
		debugAllowed = false;
		alreadyComplainedAboutMsgLen = false;
		mapped = false;
		sockListSize = SOCK_LIST_SIZE_MIN;
		sockList = new HashMap<Integer, SockDesc>(SOCK_LIST_SIZE_MIN);
		defaultLocHost = "";
		defaultLocPort = 9999;
		defaultRemHost = null;
		defaultRemPort = -1;
		connId_release_confirmed = false;
		backlog = SO_MAX_CONN;
		defaultMsgLenArgs = new Socket__API__Definitions.ro__integer(TitanNull_Type.NULL_VALUE);
		//TODO: create f__getMsgLen variable for simpleGetMsgLen function
		//defaultGetMsgLen_forConnClosedEvent = (stream, args) -> simpleGetMsgLen(stream, args);
		defaultMsgLenArgs_forConnClosedEvent = new Socket__API__Definitions.ro__integer(TitanNull_Type.NULL_VALUE);
		pureNonBlocking = false;
		poll_timeout = 1;
		max_num_of_poll = -1;
		lonely_conn_id = -1;
		lazy_conn_id_level = 0;
		sctp_PMTU_size = 0;
		broadcast = false;
		ssl_cert_per_conn = false;
		send_extended_result = false;
		dontCloseConnectionId = -1;
		ipAddrLease = new IPAddrLease();
		ipDiscConfig = new IPDiscConfig();
		globalConnOpts = new GlobalConnOpts();
		ssl_initialized = false;
		ssl_key_file = null;
		ssl_certificate_file = null;
		ssl_trustedCAlist_file = null;
		ssl_cipher_list = null;
		ssl_verify_certificate=false;
		ssl_use_session_resumption=true;
		//ssl_session = NULL;
		ssl_password = null;
		//ssl_ctx = NULL;
		ssl_reconnect_attempts = 5;
		ssl_reconnect_delay = 10000; //in milisec, so by default 0.01sec
		//memset(ssl_cookie_secret, 0, IPL4_COOKIE_SECRET_LENGTH);
		//ssl_cookie_initialized = 0;
		psk_identity = null;
		psk_identity_hint = null;
		psk_key = null;
	}

	// Call this function instead of macro IPL4_PORTREF_DEBUG or IPL4_DEBUG
	// (shouldn't use macro in Java)
	public void IPL4_DEBUG(final String fmt, final Object... args) {
		if (debugAllowed) {
			TTCN_Logger.begin_event(Severity.DEBUG_TESTPORT);
			TTCN_Logger.log_event("%s: ", get_name());
			TTCN_Logger.log_va_list(Severity.DEBUG_TESTPORT, fmt, args);
			TTCN_Logger.end_event();
		}
	}

	private void IPL4_PORTREF_DEBUG(IPL4asp__PT_PROVIDER portRef, String fmt, final Object... args) {
		if (portRef.debugAllowed) {
			TTCN_Logger.begin_event(Severity.DEBUG_TESTPORT);
			TTCN_Logger.log_event("%s: ", portRef.get_name());
			TTCN_Logger.log_va_list(Severity.DEBUG_TESTPORT, fmt, args);
			TTCN_Logger.end_event();
		}
	}

	private Result RETURN_ERROR(final int code, Result result, IPL4asp__PT_PROVIDER portRef) {
		result.get_field_errorCode().get().from_int(code);
		if (result.constGet_field_os__error__code().is_present()) {
			//TODO: os_error_code
		}
		ASP__Event event = new ASP__Event();
		event.get_field_result().operator_assign(result);
		if (portRef.globalConnOpts.extendedPortEvents == GlobalConnOpts.YES) {
			portRef.incoming_message(event);
		}
		return result;
	}

	public void set_parameter(final String parameter_name, final String parameter_value) {
		// TODO: finish SSL, SCTP parameters
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.set_parameter: enter (name: %s, value: %s)", parameter_name, parameter_value);
		if (parameter_name.equals("debug")) {
			if (parameter_value.toLowerCase().equals("yes")) {
				debugAllowed = true;
				ipDiscConfig.debugAllowed = true;
			}
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.set_parameter: enter (name: %s, value: %s)", parameter_name, parameter_value);
		} else if (parameter_name.equals("max_num_of_poll")) {
			max_num_of_poll = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("poll_timeout")) {
			poll_timeout = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("defaultListeningPort")) {
			defaultLocPort = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("defaultListeningHost")) {
			defaultLocHost = parameter_value;
		} else if (parameter_name.equals("map_behavior")) {
			if (parameter_value.equals("connect")) {
				default_mode = 1;
			} else if (parameter_value.equals("listen")) {
				default_mode = 2;
			} else {
				default_mode = 0;
			}
		} else if (parameter_name.equals("connId_release_mode")) {
			if (parameter_value.equals("confirmed")) {
				connId_release_confirmed = true;
			} else {
				connId_release_confirmed = false;
			}
		} else if (parameter_name.equals("map_protocol")) {
			if (parameter_value.equals("tcp")) {
				default_proto = 0;
			} else if (parameter_value.equals("tls")) {
				default_proto = 1;
				IPL4_USE_SSL = true;
			} else if (parameter_value.equals("sctp")) {
				default_proto = 2;
				USE_SCTP = true;
			} else if (parameter_value.equals("udp")) {
				default_proto = 3;
			}
		} else if (parameter_name.equals("RemotePort")) {
			defaultRemPort = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("RemoteHost")) {
			defaultRemHost = parameter_value;
		} else if (parameter_name.equals("backlog")) {
			backlog = Integer.valueOf(parameter_value);
			if (backlog <= 0) {
				backlog = SO_MAX_CONN;
				TtcnError.TtcnWarning(MessageFormat.format("IPL4asp__PT_PROVIDER.set_parameter: invalid backlog value set to {0}", backlog));
			}
		} else if (parameter_name.equals("sockListSizeInit")) {
			sockListSize = Integer.valueOf(parameter_value);
			if (sockListSize <= SOCK_LIST_SIZE_MIN) {
				sockListSize = SOCK_LIST_SIZE_MIN;
				TtcnError.TtcnWarning(MessageFormat.format("IPL4asp__PT_PROVIDER.set_parameter: invalid sockListSizeInit value set to {0}", sockListSize));
				sockList = new HashMap<Integer, SockDesc>(sockListSize);
			}
		} else if (parameter_name.equals("pureNonBlocking")) {
			if (parameter_value.equals("YES")) {
				pureNonBlocking = true;
			}
		} else if (parameter_name.equals("useExtendedResult")) {
			if (parameter_value.equals("YES")) {
				send_extended_result = true;
			}
		} else if (parameter_name.equals("lazy_conn_id_handling")) {
			if (parameter_value.equals("YES")) {
				lazy_conn_id_level = 1;
			} else {
				lazy_conn_id_level = 0;
			}
		} else if (parameter_name.equals("sctp_path_mtu_size")) {
			sctp_PMTU_size = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("ipAddressDiscoveryType")) {
			if (parameter_value.equals("DHCP_OR_ARP")) {
				ipDiscConfig.type = IPDiscConfig.Type.DHCP_OR_ARP;
			} else if (parameter_value.equals("DHCP")) {
				ipDiscConfig.type = IPDiscConfig.Type.DHCP;
			} else if (parameter_value.equals("ARP")) {
				ipDiscConfig.type = IPDiscConfig.Type.ARP;
			}
		} else if (parameter_name.equals("freebind")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.freebind = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.freebind = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("interfaceName")) {
			ipDiscConfig.expIfName = new TitanCharString(parameter_value);
		} else if (parameter_name.equals("interfaceIpAddress")) {
			ipDiscConfig.expIfIpAddress = new TitanCharString(parameter_value);
		} else if (parameter_name.equals("excludedInterfaceIpAddress")) {
			ipDiscConfig.exclIfIpAddress = new TitanCharString(parameter_value);
		} else if (parameter_name.equals("ethernetAddressStart")) {
			ipDiscConfig.ethernetAddress = new TitanCharString(parameter_value);
		} else if (parameter_name.equals("leaseTime")) {
			ipDiscConfig.leaseTime = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("leaseFile")) {
			ipDiscConfig.leaseFile = new TitanCharString(parameter_value);
		} else if (parameter_name.equals("numberOfIpAddressesToFind")) {
			ipDiscConfig.nOfAddresses = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("dhcpMsgRetransmitCount")) {
			ipDiscConfig.dhcpMsgRetransmitCount = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("dhcpMsgRetransmitPeriodInms")) {
			ipDiscConfig.dhcpMsgRetransmitPeriodInms = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("dhcpMaxParallelRequestCount")) {
			ipDiscConfig.dhcpMaxParallelRequestCount = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("dhcpTimeout")) {
			ipDiscConfig.dhcpTimeout = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("arpMsgRetransmitCount")) {
			ipDiscConfig.arpMsgRetransmitCount = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("arpMsgRetransmitPeriodInms")) {
			ipDiscConfig.arpMsgRetransmitPeriodInms = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("arpMaxParallelRequestCount")) {
			ipDiscConfig.arpMaxParallelRequestCount = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("tcpReuseAddress")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.tcpReuseAddr = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.tcpReuseAddr = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("sslReuseAddress")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.tcpReuseAddr = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.tcpReuseAddr = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("udpReuseAddress")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.udpReuseAddr = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.udpReuseAddr = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("sctpReuseAddress")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.sctpReuseAddr = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.sctpReuseAddr = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("tcpKeepAlive")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.tcpKeepAlive = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.tcpKeepAlive = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("tcpKeepCount")) {
			globalConnOpts.tcpKeepCnt = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("tcpKeepIdle")) {
			globalConnOpts.tcpKeepIdle = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("tcpKeepInterval")) {
			globalConnOpts.tcpKeepIntvl = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("sslKeepAlive")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.tcpKeepAlive = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.tcpKeepAlive = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("sslKeepCount")) {
			globalConnOpts.tcpKeepCnt = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("sslKeepIdle")) {
			globalConnOpts.tcpKeepIdle = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("sslKeepInterval")) {
			globalConnOpts.tcpKeepIntvl = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("extendedPortEvents")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.extendedPortEvents = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.extendedPortEvents = GlobalConnOpts.NO;
			}
			// sctp specific params starts here
		} else if (parameter_name.equals("sinit_num_ostreams")) {
			globalConnOpts.sinit_num_ostreams = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("sinit_max_instreams")) {
			globalConnOpts.sinit_max_instreams = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("sinit_max_attempts")) {
			globalConnOpts.sinit_max_attempts = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("sinit_max_init_timeo")) {
			globalConnOpts.sinit_max_init_timeo = Integer.valueOf(parameter_value);
		} else if (parameter_name.equals("sctp_data_io_event")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.sctp_data_io_event = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.sctp_data_io_event = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("sctp_association_event")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.sctp_association_event = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.sctp_association_event = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("sctp_address_event")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.sctp_address_event = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.sctp_address_event = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("sctp_send_failure_event")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.sctp_send_failure_event = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.sctp_send_failure_event = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("sctp_peer_error_event")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.sctp_peer_error_event = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.sctp_peer_error_event = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("sctp_shutdown_event")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.sctp_shutdown_event = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.sctp_shutdown_event = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("sctp_partial_delivery_event")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.sctp_partial_delivery_event = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.sctp_partial_delivery_event = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("sctp_adaptation_layer_event")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.sctp_adaptation_layer_event = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.sctp_adaptation_layer_event = GlobalConnOpts.NO;
			}
		} else if (parameter_name.equals("sctp_authentication_event")) {
			if (parameter_value.equals("YES")) {
				globalConnOpts.sctp_authentication_event = GlobalConnOpts.YES;
			} else if (parameter_value.equals("NO")) {
				globalConnOpts.sctp_authentication_event = GlobalConnOpts.NO;
			}
		}
		//TODO: finish
	}

	@Override
	public void Handle_Event(SelectableChannel channel, boolean is_readable, boolean is_writeable) {
		if (is_writeable && !is_readable) {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Writable: channel: %s", channel.toString());
			int connId = 0;
			Iterator<Map.Entry<Integer, SockDesc>> iterator = sockList.entrySet().iterator();
			while (iterator.hasNext()) {
				Map.Entry<Integer, SockDesc> entry = iterator.next();
				if (entry.getValue().sock.equals(channel)) {
					connId = entry.getKey();
					break;
				}
			}
			if (pureNonBlocking) {
				if (connId != 0) {
					//TODO: Add SSL layer
				} else {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Writable: Error: channel not found");
				}
			} else {
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Writable: Error: pureNonBlocking is FALSE");
			}
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Writable: Leave.");
			return;
		}
		if (is_readable && !is_writeable) {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: enter, channel: %s", channel.toString());

			int connId = 0;
			Iterator<Map.Entry<Integer, SockDesc>> iterator = sockList.entrySet().iterator();
			while (iterator.hasNext()) {
				Map.Entry<Integer, SockDesc> entry = iterator.next();
				if (entry.getValue().sock.equals(channel)) {
					connId = entry.getKey();
					break;
				}
			}

			if (connId == 0) {
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: Error: channel not found");
				return;
			}
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: connId: %d READABLE   sock: %s, type: %s, sslState: %s", connId, sockList.get(connId).sock, sockList.get(connId).type, sockList.get(connId).sslState);

			ASP__RecvFrom asp = new ASP__RecvFrom();
			asp.get_field_connId().operator_assign(connId);
			asp.get_field_userData().operator_assign(sockList.get(connId).userData);
			// FIXME: remote addr and and remoteport
			if (sockList.get(connId).sock instanceof DatagramChannel) {
				if (((DatagramChannel) sockList.get(connId).sock).socket().getInetAddress() != null) {
					asp.get_field_remName().operator_assign(((DatagramChannel) sockList.get(connId).sock).socket().getInetAddress().toString());
					asp.get_field_remPort().operator_assign(((DatagramChannel) sockList.get(connId).sock).socket().getPort());
				} else {
					asp.get_field_remName().operator_assign("");
					asp.get_field_remPort().operator_assign(0);
				}
			} else {
				if (sockList.get(connId).remoteaddr != null && sockList.get(connId).remoteport != null) {
					asp.get_field_remName().operator_assign(sockList.get(connId).remoteaddr);
					asp.get_field_remPort().operator_assign(sockList.get(connId).remoteport);
				} else {
					asp.get_field_remName().operator_assign("");
					asp.get_field_remPort().operator_assign(0);
				}

			}
			asp.get_field_locName().operator_assign(sockList.get(connId).localaddr);
			asp.constGet_field_locPort().operator_assign(sockList.get(connId).localport);
			asp.get_field_proto().get_field_tcp().operator_assign(TitanNull_Type.NULL_VALUE);

			int len = -3;
			ByteBuffer buf = ByteBuffer.allocate(RECV_MAX_LEN);
			buf.clear();
			if ((sockList.get(connId).ssl_tls_type != SSL_TLS_Type.NONE) && ((sockList.get(connId).sslState == SSL_STATES.STATE_CONNECTING) || (sockList.get(connId).sslState == SSL_STATES.STATE_HANDSHAKING))) {
				// 1st branch: handle SSL/TLS handshake
				if (sockList.get(connId).type == SockType.IPL4asp_UDP) {
					asp.get_field_proto().get_field_dtls().get_field_udp().operator_assign(TitanNull_Type.NULL_VALUE);
				} else {
					asp.get_field_proto().get_field_ssl().operator_assign(TitanNull_Type.NULL_VALUE);
				}
				// TODO: implement SSL
			} else if ((sockList.get(connId).type == SockType.IPL4asp_TCP_LISTEN) || (sockList.get(connId).type == SockType.IPL4asp_SCTP_LISTEN)) {
				// 2nd branch: handle TCP/SCTP server accept
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: incoming connection requested");
				SocketChannel sock = null;
				if (sockList.get(connId).sock instanceof ServerSocketChannel) {
					try {
						sock = ((ServerSocketChannel) sockList.get(connId).sock).accept();
					} catch (IOException e) {
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: tcp accept error: %s", e.getMessage());
						sendError(new PortError(PortError.enum_type.ERROR__SOCKET), connId, 0);
						return;
					}
					try {
						sock.configureBlocking(false);
					} catch (IOException e) {
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: fcntl O_NONBLOCK on socket %s failed: %s", sock, e.getMessage());
						try {
							sock.close();
							sendError(new PortError(PortError.enum_type.ERROR__SOCKET), connId, 0);
							return;
						} catch (IOException e1) {
							IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: Error on socket closing: %s", e1.getMessage());
							return;
						}
					}
					int k = ConnAdd(SockType.IPL4asp_TCP, sock, sockList.get(connId).ssl_tls_type == SSL_TLS_Type.SERVER ? SSL_TLS_Type.CLIENT : SSL_TLS_Type.NONE, null, connId);
					if (k == -1) {
						sendError(new PortError(PortError.enum_type.ERROR__INSUFFICIENT__MEMORY), connId, 0);
						return;
					}
					// if we are not doing SSL, then report the connection opened
					// if SSL is also triggered, we will report the connOpened at the end of the handshake
					if(sockList.get(connId).ssl_tls_type == SSL_TLS_Type.NONE) {
						reportConnOpened(k);
					}
				} /*else if (sockList.get(connId).sock instanceof SctpServerChannel) {
					SctpChannel sctpSock = null;
					try {
						sctpSock = ((SctpServerChannel) sockList.get(connId).sock).accept();
					} catch (IOException e) {
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: sctp accept error: %s", e.getMessage());
						sendError(new PortError(PortError.enum_type.ERROR__SOCKET), connId, 0);
						return;
					}
					try {
						sctpSock.configureBlocking(false);
					} catch (IOException e) {
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: fcntl O_NONBLOCK on socket %s failed: %s", sock, e.getMessage());
						try {
							sctpSock.close();
							sendError(new PortError(PortError.enum_type.ERROR__SOCKET), connId, 0);
							return;
						} catch (IOException e1) {
							IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: Error on socket closing: %s", e1.getMessage());
							return;
						}
					}
					int k = ConnAdd(SockType.IPL4asp_SCTP, sctpSock, sockList.get(connId).ssl_tls_type, null, connId);
					if (k == -1) {
						sendError(new PortError(PortError.enum_type.ERROR__INSUFFICIENT__MEMORY), connId, 0);
						return;
					}
					// if we are not doing SSL, then report the connection opened
					// if SSL is also triggered, we will report the connOpened at the end of the handshake
					if(sockList.get(connId).ssl_tls_type == SSL_TLS_Type.NONE) {
						reportConnOpened(k);
					}
				}*/
			} else {
				// 3rd branch: normal data receiving
				switch (sockList.get(connId).type) {
				case IPL4asp_UDP:
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: udp message received");
					// normal UDP receiving first
					if ((sockList.get(connId).ssl_tls_type == SSL_TLS_Type.NONE) ||
							// if DTLS+SRTP, then no demultiplex yet, just pass the incoming packet as UDP to the testcase
							((sockList.get(connId).dtlsSrtpProfiles != null) && (sockList.get(connId).sslState == SSL_STATES.STATE_NORMAL))) {
						asp.get_field_proto().get_field_udp().operator_assign(TitanNull_Type.NULL_VALUE);
						if (sockList.get(connId).sock instanceof DatagramChannel) {
							try {
								SocketAddress sa = ((DatagramChannel) sockList.get(connId).sock).receive(buf);
								len = buf.position();
								if ((len >= 0) && (sa == null)) {
									sendError(new PortError(PortError.enum_type.ERROR__HOSTNAME), connId, 0);
								}
							} catch (IOException e) {
								IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: udp receive error: %s", e.getMessage());
								sendError(new PortError(PortError.enum_type.ERROR__SOCKET), connId, 0);
								break;
							}
						}
					} else {
						asp.get_field_proto().get_field_dtls().get_field_udp().operator_assign(TitanNull_Type.NULL_VALUE);
						//TODO: finish DTLS
					}
					if (len == -1) {
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: udp recvfrom error: The channel has reached end-of-stream");
						sendError(new PortError(PortError.enum_type.ERROR__SOCKET), connId, 0);
						break;
						//TODO: add ssl
					} else if ((len == 0) && (sockList.get(connId).ssl_tls_type != SSL_TLS_Type.NONE)) {
						reportRemainingData_beforeConnClosed(new TitanInteger(connId), asp.constGet_field_remName(), asp.constGet_field_remPort(), asp.constGet_field_locName(), asp.constGet_field_locPort(), asp.constGet_field_proto(), asp.get_field_userData().get_int());
						sendConnClosed(new TitanInteger(connId), asp.constGet_field_remName(), asp.constGet_field_remPort(), asp.constGet_field_locName(), asp.constGet_field_locPort(), asp.constGet_field_proto(), asp.get_field_userData().get_int());
						if (ConnDel(connId, true) == -1) {
							IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: ConnDel failed");
						}
					}

					if (len > 0) {
						if(sockList.get(connId).ssl_tls_type == SSL_TLS_Type.NONE) {
							byte received[] = new byte[len];
							buf.rewind();
							buf.get(received, 0, len);
							asp.get_field_msg().operator_assign(new TitanOctetString(received));
							incoming_message(asp);
						} else {
							// throw warning if connId is SRTP & the incoming packet is DTLS
							if (sockList.get(connId).dtlsSrtpProfiles != null) {
								IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: first byte is %d.", buf.array()[0]);
								//TODO: implement rest if needed
							} else {
								// no fragmentation in UDP, DTLS neither. no need to call the getMsgLen
								asp.get_field_msg().operator_assign(new TitanOctetString(sockList.get(connId).buf.get_data()));
								sockList.get(connId).buf.set_pos(len);
								sockList.get(connId).buf.cut();
							}
							incoming_message(asp);
						}
					}
					break;
				case IPL4asp_TCP_LISTEN:
					break;
				case IPL4asp_TCP:
					if(sockList.get(connId).ssl_tls_type == SSL_TLS_Type.NONE) {
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: TCP recvfrom enter:");
						asp.get_field_proto().get_field_tcp().operator_assign(TitanNull_Type.NULL_VALUE);
						if (sockList.get(connId).sock instanceof SocketChannel) {
							try {
								len = ((SocketChannel) sockList.get(connId).sock).read(buf);
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}

					} else {
						//TODO: implement SSL
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: SSL recvfrom enter:");
						asp.get_field_proto().get_field_ssl().operator_assign(TitanNull_Type.NULL_VALUE);

						if (!isConnIdValid(connId)) {
							IPL4_DEBUG("IPL4asp__PT_PROVIDER.receive_message_on_fd: invalid connId: %d", connId);
							break;
						}
					}
					if (len > 0) {
						// in normal case, this is where we put the incoming data in the buffer
						// in SSL case, the receive_ssl_message_on_fd() already placed it there
						if(sockList.get(connId).ssl_tls_type == SSL_TLS_Type.NONE) {
							buf.rewind();
							byte received[] = new byte[len];
							buf.get(received, 0, len);
							sockList.get(connId).buf.put_s(received);
						}

						boolean msgFound = false;
						do {
							if (sockList.get(connId).msgLen == -1) {
								TitanOctetString oct = new TitanOctetString();
								sockList.get(connId).buf.get_string(oct);
								//TODO: implement function pointers
								if (sockList.get(connId).getMsgLen == null) {
									sockList.get(connId).msgLen = simpleGetMsgLen(oct, sockList.get(connId).msgLenArgs).get_int();
								} else {
									sockList.get(connId).msgLen = sockList.get(connId).getMsgLen.invoke(oct, sockList.get(connId).msgLenArgs).get_int();
								}
							}
							if (!alreadyComplainedAboutMsgLen && (sockList.get(connId).type == SockType.IPL4asp_TCP)) {
								TtcnError.TtcnWarning(String.format("There is no GetMsgLen function registered for connId: %d. The messages will not be dissected on this connection! This warning is logged only once per testport.", connId));
								alreadyComplainedAboutMsgLen = true;
							}

							if (sockList.get(connId).msgLen == 0) { // The GetMsgLen function should not return 0.
								// If it returns 0, then we log what we can, and stop the component.
								TitanOctetString oct = new TitanOctetString();
								sockList.get(connId).buf.get_string(oct);
								TTCN_Logger.begin_event(Severity.ERROR_UNQUALIFIED);
								TTCN_Logger.log_event("%s: MsgLen calculation function returned 0 on connection %s:%u <-> %s:%u. Received data: ", get_name(), sockList.get(connId).localaddr.get_value(), sockList.get(connId).localport.get_long(), sockList.get(connId).remoteaddr.get_value(), sockList.get(connId).remoteport.get_long());
								oct.log();
								TTCN_Logger.end_event();
								throw new TtcnError("MsgLen returned 0");
							} else if (sockList.get(connId).msgLen == -2) {	// The GetMsgLen function returned -2 means
								// it is impossible to determine the length of the message -> report & close
								TitanOctetString oct = new TitanOctetString();
								sockList.get(connId).buf.get_string(oct);
								TTCN_Logger.begin_event(Severity.WARNING_UNQUALIFIED);
								TTCN_Logger.log_event("%s: MsgLen calculation function reported length calculation error on connection %s:%u <-> %s:%u. Received data: ", get_name(), sockList.get(connId).localaddr.get_value(), sockList.get(connId).localport.get_long(), sockList.get(connId).remoteaddr.get_value(), sockList.get(connId).remoteport.get_long());
								oct.log();
								TTCN_Logger.end_event();
								//TODO: implement sendError

								// close the connection
								len = 0;  // leave the loop and close the connection in the code below
								break;
							} else {
								msgFound = (sockList.get(connId).msgLen != -1) && (sockList.get(connId).msgLen <= sockList.get(connId).buf.get_len());
								if (msgFound) {
									IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: message length: (%d/%d bytes)\n", sockList.get(connId).msgLen, sockList.get(connId).buf.get_len());
									asp.get_field_msg().operator_assign(new TitanOctetString(sockList.get(connId).buf.get_data()));
									sockList.get(connId).buf.set_pos(sockList.get(connId).msgLen);
									sockList.get(connId).buf.cut();
									if (lazy_conn_id_level != 0 && sockListCnt == 1 && lonely_conn_id != -1) {
										asp.get_field_connId().operator_assign(-1);
									}
									incoming_message(asp);
									sockList.get(connId).msgLen = -1;
								}
							}
						} while (msgFound && sockList.get(connId).buf.get_len() != 0);
						if (sockList.get(connId).buf.get_len() != 0) {
							IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: incomplete message (%d bytes)\n", sockList.get(connId).buf.get_len());
						}
					}
					if (len == -1) {
						//TODO: implement
					}
					break;
				case IPL4asp_SCTP_LISTEN:
					break;
				case IPL4asp_SCTP:
					ASP__Event event = new ASP__Event();
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: sctp message received");

					IPL4_DEBUG("IPL4asp__PT_PROVIDER.Handle_Event Readable: sctp peername and sockname obtained");
					//FIXME: maybe need an extra condition for type check
					//SctpChannel sock = (SctpChannel) sockList.get(connId).sock;
				default:
					break;
				}
			}

		}
	}

	private void reportConnOpened(final int client_id) {
		ASP__Event event = new ASP__Event();

		event.get_field_connOpened().get_field_remName().operator_assign(sockList.get(client_id).remoteaddr);
		event.get_field_connOpened().get_field_remPort().operator_assign(sockList.get(client_id).remoteport);
		event.get_field_connOpened().get_field_locName().operator_assign(sockList.get(client_id).localaddr);
		event.get_field_connOpened().get_field_locPort().operator_assign(sockList.get(client_id).localport);

		if (sockList.get(client_id).type == SockType.IPL4asp_UDP) {
			if (sockList.get(client_id).ssl_tls_type != SSL_TLS_Type.NONE) {
				event.get_field_connOpened().get_field_proto().get_field_dtls().get_field_udp().operator_assign(TitanNull_Type.NULL_VALUE);
			} else {
				IPL4_DEBUG( "IPL4asp__PT_PROVIDER.reportConnOpened: unhandled UDP case!");
			}
		} else if ((sockList.get(client_id).type == SockType.IPL4asp_TCP) || (sockList.get(client_id).type == SockType.IPL4asp_TCP_LISTEN)) {
			if (sockList.get(client_id).ssl_tls_type != SSL_TLS_Type.NONE) {
				event.get_field_connOpened().get_field_proto().get_field_ssl().operator_assign(TitanNull_Type.NULL_VALUE);
			} else {
				event.get_field_connOpened().get_field_proto().get_field_tcp().operator_assign(TitanNull_Type.NULL_VALUE);
			}
		} else if ((sockList.get(client_id).type == SockType.IPL4asp_SCTP) || (sockList.get(client_id).type == SockType.IPL4asp_SCTP_LISTEN)) {
			if (sockList.get(client_id).ssl_tls_type != SSL_TLS_Type.NONE) {
				event.get_field_connOpened().get_field_proto().get_field_dtls().get_field_sctp().operator_assign(new SctpTuple(new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(Socket__API__Definitions.SocketList.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE)));
			} else {
				event.get_field_connOpened().get_field_proto().get_field_sctp().operator_assign(new SctpTuple(new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(Socket__API__Definitions.SocketList.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE)));
			}
		} else {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.reportConnOpened: unhandled protocol!");
		}
		set_dscp_option(sockList.get(client_id).sock);
		event.get_field_connOpened().get_field_connId().operator_assign(client_id);
		event.get_field_connOpened().get_field_userData().operator_assign(sockList.get(client_id).userData);
		incoming_message(event);
	}

	@Override
	protected void user_map(String system_port) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.user_map(%s): enter", system_port);
		dontCloseConnectionId = -1;
		closingPeerLen = 0;
		lonely_conn_id = -1;
		if (USE_IPL4_EIN_SCTP) {
			// if(!native_stack)
			// TODO: implement do_bind()
		}
		mapped = true;

		ProtoTuple pt;
		OptionList op;
		Result res;

		switch (default_mode) {
		case 1: // connect
			if (lazy_conn_id_level != 1) {
				throw new TtcnError(String.format("IPL4asp__PT_PROVIDER.user_map(%s): Autoconnect: The lazy_conn_id_level should be \"Yes\" ", system_port));
			}
			if (defaultRemHost == null) {
				throw new TtcnError(String.format("IPL4asp__PT_PROVIDER.user_map(%s): Autoconnect: The remote host should be specified.", system_port));
			}
			if (defaultRemPort == -1) {
				throw new TtcnError(String.format("IPL4asp__PT_PROVIDER.user_map(%s): Autoconnect: The remote port should be specified.", system_port));
			}
			pt = new ProtoTuple();
			pt.get_field_unspecified();
			switch (default_proto) {
			case 1: // TLS
				pt.get_field_ssl();
				break;
			case 2: // SCTP
				pt.get_field_sctp();
				break;
			case 3: // UDP
				pt.get_field_udp();
				break;
			default: // TCP
				pt.get_field_tcp();
				break;
			}
			op = new OptionList(TitanNull_Type.NULL_VALUE);
			res = f__IPL4__PROVIDER__connect(this, new TitanCharString(defaultRemHost), new TitanInteger(defaultRemPort), new TitanCharString(defaultLocHost), new TitanInteger(defaultLocPort), new TitanInteger(-1), pt, op);
			if (res.constGet_field_os__error__code().is_present()) {
				throw new TtcnError(String.format(
						"IPL4asp__PT_PROVIDER.user_map(%s): Autoconnect: Can not connect: %d %s ", system_port,
						res.constGet_field_errorCode().ispresent()
						? res.constGet_field_os__error__code().constGet().get_int()
								: -1,
								res.constGet_field_os__error__text().is_present()
								? res.constGet_field_os__error__text().constGet().get_value().toString()
										: ""));
			}
			break;
		case 2: // listen
			if (lazy_conn_id_level != 0) {
				throw new TtcnError(String.format("IPL4asp__PT_PROVIDER.user_map(%s): Autolisten: The lazy_conn_id_level should be \"No\" ", system_port));
			}
			pt = new ProtoTuple();
			pt.get_field_unspecified();
			switch (default_proto) {
			case 1: // TLS
				pt.get_field_ssl();
				break;
			case 2: // SCTP
				pt.get_field_sctp();
				break;
			case 3: // UDP
				pt.get_field_udp();
				break;
			default: // TCP
				pt.get_field_tcp();
				break;
			}
			op = new OptionList(TitanNull_Type.NULL_VALUE);
			res = f__IPL4__PROVIDER__listen(this, new TitanCharString(defaultLocHost), new TitanInteger(defaultLocPort),
					pt, op);

			if (res.constGet_field_errorCode().is_present()) {
				throw new TtcnError(String.format("IPL4asp__PT_PROVIDER.user_map(%s): Autolisten: Can not listen: %d %s ", system_port, res.constGet_field_os__error__code().is_present() ? res.constGet_field_os__error__code().constGet().get_int() : -1, res.constGet_field_os__error__text().is_present()
						? res.constGet_field_os__error__text().constGet().get_value().toString() : ""));
			}
			break;
		default:
			// do nothing
			break;
		}
	}

	//FIXME: don't close connection correctly
	@Override
	protected void user_unmap(String system_port) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.user_unmap(%s): enter", system_port);
		mapped = false;
		if (sockListCnt > 0) {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER::user_unmap: There are %d open connections", sockListCnt);
		}
		if (sockList != null) {
			Iterator<Map.Entry<Integer, SockDesc>> socketListIterator = sockList.entrySet().iterator();
			while (socketListIterator.hasNext()) {
				Map.Entry<Integer, SockDesc> socketListItem = socketListIterator.next();
				ConnDel(socketListItem.getKey(), true);
				socketListIterator.remove();
			}
		}
		sockListCnt = 0;
		if (USE_IPL4_EIN_SCTP) {
			// TODO: if(!native_stack) do_unbind();
		}
		sockList.clear();
		if (globalConnOpts.dtlsSrtpProfiles != null && globalConnOpts.dtlsSrtpProfiles.isEmpty()) {
			globalConnOpts.dtlsSrtpProfiles = null;
		}
		lonely_conn_id = -1;
		try {
			Uninstall_Handler();
		} catch (IOException e) {
			System.err.println("Uninstall_Handler error: " + e.getMessage());
		}
	}

	@Override
	protected void user_start() {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.user_start: enter");
	}

	@Override
	protected void user_stop() {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.user_stop: enter");
	}

	private boolean getAndCheckSockType(final int connId, final ProtoTuple.union_selection_type proto, SockType type) {
		if (!isConnIdValid(connId)) {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.getAndCheckSockType: invalid connId: %d", connId);
			return false;
		}
		type = sockList.get(connId).type;
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.getAndCheckSockType: sock type is: %s", type.name());
		if (proto != ProtoTuple.union_selection_type.UNBOUND_VALUE && proto != ProtoTuple.union_selection_type.ALT_unspecified) {
			/* Proto is specified. It is used for checking only. */
			if (((type == SockType.IPL4asp_UDP) && (proto != ProtoTuple.union_selection_type.ALT_udp)
					&& (proto != ProtoTuple.union_selection_type.ALT_dtls))
					|| (((type == SockType.IPL4asp_TCP_LISTEN) || (type == SockType.IPL4asp_TCP))
							&& ((proto != ProtoTuple.union_selection_type.ALT_tcp) && (proto != ProtoTuple.union_selection_type.ALT_ssl)))
					|| (((type == SockType.IPL4asp_SCTP_LISTEN) || (type == SockType.IPL4asp_SCTP))
							&& (proto != ProtoTuple.union_selection_type.ALT_sctp))) {
				return false;
			}
		}
		return true;
	}

	private int sendNonBlocking(final TitanInteger id, SocketAddress sa, SockType type, final TitanOctetString msg, Result result, final ProtoTuple protoTuple) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.sendNonBlocking: enter: connId: %d", id.get_int());

		SelectableChannel sock = sockList.get(id.get_int()).sock;
		if (sock == null) {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.sendNonBlocking: Socket is null!");
			setResult(result, new PortError(PortError.enum_type.ERROR__SOCKET), id);
			return -1;
		}
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.sendNonBlocking: socket: %s", sock.toString());
		TitanOctetString ptr = msg;
		ByteBuffer byteBuffer = ByteBuffer.wrap(ptr.get_value());

		// TODO: implement SSL

		while (byteBuffer.hasRemaining()) {
			switch (type) {
			case IPL4asp_UDP:
				if (sockList.get(id.get_int()).ssl_tls_type == SSL_TLS_Type.NONE || protoTuple.get_selection() == ProtoTuple.union_selection_type.ALT_udp) {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.sendNonBlocking, sending unencrypted...");
					if (sock instanceof DatagramChannel) {
						try {
							if (sa != null) {
								((DatagramChannel) sock).send(byteBuffer, sa);
							} else {
								((DatagramChannel) sock).write(byteBuffer);
							}
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
				}

				break;
			case IPL4asp_TCP_LISTEN:
				if (sockList.get(id.get_int()).ssl_tls_type == SSL_TLS_Type.NONE || protoTuple.get_selection() == ProtoTuple.union_selection_type.ALT_udp) {
					// if UDP is requested over the DTLS, then send UDP unencrypted
					//FIXME: need to test it
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.sendNonBlocking, sending unencrypted...");
					try {
						TTCN_Snapshot.selector.get().select();
						Set<SelectionKey> selectedKeys = TTCN_Snapshot.selector.get().selectedKeys();
						Iterator<SelectionKey> keyIterator = selectedKeys.iterator();
						while (keyIterator.hasNext()) {
							SelectionKey selectionKey = keyIterator.next();
							if (selectionKey.isReadable()) {
								SocketChannel client = (SocketChannel) selectionKey.channel();
								client.write(byteBuffer);
							}
							keyIterator.remove();
						}
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				break;
			case IPL4asp_TCP:
				if (sockList.get(id.get_int()).ssl_tls_type == SSL_TLS_Type.NONE || protoTuple.get_selection() == ProtoTuple.union_selection_type.ALT_udp) {
					// if UDP is requested over the DTLS, then send UDP unencrypted
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.sendNonBlocking, sending unencrypted...");
					if (sock instanceof SocketChannel) {
						try {
							((SocketChannel) sock).write(byteBuffer);
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
			default:
				break;
			}
		}
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.sendNonBlocking: leave");
		return byteBuffer.position();
	}

	private int sendNonBlocking(final TitanInteger id, SocketAddress sa, SockType type, final TitanOctetString msg, Result result) {
		ProtoTuple protoTuple = new ProtoTuple();
		protoTuple.get_field_unspecified().operator_assign(TitanNull_Type.NULL_VALUE);
		return sendNonBlocking(id, sa, type, msg, result, protoTuple);
	}

	protected void outgoing_send(final IPL4asp__Types.ASP__SendTo send_par) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.outgoing_send: ASP Send: enter");
		testIfInitialized();
		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		outgoing_send_core(send_par, result);
		if (result.constGet_field_errorCode().ispresent()) {
			ASP__Event event = new ASP__Event();
			if (send_extended_result) {
				event.get_field_extended__result().get_field_errorCode().operator_assign(result.constGet_field_errorCode());
				event.get_field_extended__result().get_field_connId().operator_assign(result.constGet_field_connId());
				event.get_field_extended__result().get_field_os__error__code().operator_assign(result.constGet_field_os__error__code());
				event.get_field_extended__result().get_field_os__error__text().operator_assign(result.constGet_field_os__error__text());
				event.get_field_extended__result().get_field_msg().operator_assign(send_par.constGet_field_msg());
			} else {
				event.get_field_result().operator_assign(result);
			}
			incoming_message(event);
		}
	}

	public int outgoing_send_core(final ASP__SendTo asp, Result result) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.outgoing_send_core: ASP SendTo: enter");
		testIfInitialized();
		SockType type = null;
		SocketAddress to = null;
		int local_conn_id = asp.constGet_field_connId().get_int();
		if(lazy_conn_id_level != 0 && local_conn_id == -1) {
			local_conn_id = lonely_conn_id;
		}
		ProtoTuple.union_selection_type proto = ProtoTuple.union_selection_type.ALT_unspecified;
		if (asp.constGet_field_proto().is_present()) {
			proto = asp.constGet_field_proto().constGet().get_selection();
		}
		if (getAndCheckSockType(local_conn_id, proto, type)) {
			if (asp.constGet_field_remPort().is_less_than(0) || asp.constGet_field_remPort().is_greater_than(65535)) {
				setResult(result, new PortError(PortError.enum_type.ERROR__INVALID__INPUT__PARAMETER), asp.get_field_connId());
				return -1;
			}
			type = sockList.get(local_conn_id).type;
			switch (type) {
			case IPL4asp_UDP:
			case IPL4asp_TCP_LISTEN:
			case IPL4asp_TCP:
				to = setSockAddr(asp.constGet_field_remName().get_value().toString(), asp.constGet_field_remPort().get_int());
				if (to == null) {
					setResult(result, new PortError(PortError.enum_type.ERROR__HOSTNAME), asp.get_field_connId());
					return -1;
				}
				break;
			default:
				setResult(result, new PortError(PortError.enum_type.ERROR__UNSUPPORTED__PROTOCOL), asp.get_field_connId());
				return -1;
			}
			if (asp.constGet_field_proto().is_present()) {
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.outgoing_send_core: ASP SendTo: calling sendNonBlocking with proto");
				return sendNonBlocking(new TitanInteger(local_conn_id), to, type, asp.constGet_field_msg(), result, asp.constGet_field_proto().constGet());
			} else {
				return sendNonBlocking(new TitanInteger(local_conn_id), to, type, asp.constGet_field_msg(), result);
			}
		} else {
			setResult(result, new PortError(PortError.enum_type.ERROR__INVALID__INPUT__PARAMETER), asp.get_field_connId());
		}
		return -1;
	}

	protected void outgoing_send(IPL4asp__Types.ASP__Send send_par) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.outgoing_send: ASP Send: enter");
		testIfInitialized();
		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		outgoing_send_core(send_par, result);
		if (result.constGet_field_errorCode().ispresent()) {
			ASP__Event event = new ASP__Event();
			if (send_extended_result) {
				event.get_field_extended__result().get_field_errorCode().operator_assign(result.constGet_field_errorCode());
				event.get_field_extended__result().get_field_connId().operator_assign(result.constGet_field_connId());
				event.get_field_extended__result().get_field_os__error__code().operator_assign(result.constGet_field_os__error__code());
				event.get_field_extended__result().get_field_os__error__text().operator_assign(result.constGet_field_os__error__text());
				event.get_field_extended__result().get_field_msg().operator_assign(send_par.constGet_field_msg());
			} else {
				event.get_field_result().operator_assign(result);
			}
			incoming_message(event);
		}
	}

	public int outgoing_send_core(final IPL4asp__Types.ASP__Send asp, Result result) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.outgoing_send_core: ASP Send: enter");
		testIfInitialized();
		SockType type = null;
		int local_conn_id = asp.constGet_field_connId().get_int();
		if (lazy_conn_id_level != 0 && asp.constGet_field_connId().get_int() == -1) {
			local_conn_id = lonely_conn_id;
		}
		ProtoTuple.union_selection_type proto = ProtoTuple.union_selection_type.ALT_unspecified;
		if (asp.constGet_field_proto().is_present()) {
			proto = asp.constGet_field_proto().constGet().get_selection();
		}
		if (getAndCheckSockType(local_conn_id, proto, type)) {
			if (asp.constGet_field_proto().ispresent()) {
				type = sockList.get(local_conn_id).type;
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.outgoing_send_core: ASP Send: calling sendNonBlocking with proto");
				return sendNonBlocking(new TitanInteger(local_conn_id), null, type, asp.constGet_field_msg(), result, asp.constGet_field_proto().constGet());
			} else {
				type = sockList.get(local_conn_id).type;
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.outgoing_send_core: ASP Send: calling sendNonBlocking without proto");
				return sendNonBlocking(new TitanInteger(local_conn_id), null, type, asp.constGet_field_msg(), result);
			}
		} else {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.outgoing_send_core: ASP Send: INVALID INPUT PARAMETER");
			setResult(result, new PortError(PortError.enum_type.ERROR__INVALID__INPUT__PARAMETER), asp.get_field_connId());
		}
		return -1;
	}

	protected abstract void incoming_message(final Socket__API__Definitions.PortEvent incoming_par);

	protected abstract void incoming_message(final IPL4asp__Types.ASP__RecvFrom incoming_par);

	protected abstract void incoming_message(final IPL4asp__Types.ASP__ConnId__ReadyToRelease incoming_par);

	public SocketAddress setSockAddr(final String name, final int port) {
		SocketAddress socketAddress;
		int addrtype = -1;
		if (name == null || port < 0) {
			return null;
		}
		sockAddr = new InetSocketAddress(name, port);
		socketAddress = new InetSocketAddress(name, port);
		if (sockAddr.getAddress() instanceof Inet4Address) {
			addrtype = AF_INET;
		} else if (sockAddr.getAddress() instanceof Inet6Address) {
			addrtype = AF_INET6;
			USE_IPV6 = true;
		}
		return socketAddress;
	}

	public SocketAddress SetLocalSockAddr(final String debug_str, IPL4asp__PT_PROVIDER portRef,
			final int def_addr_family, final String locName, final int locPort) {
		SocketAddress localAddr = null;
		boolean locName_empty = locName.isEmpty();
		String def_loc_host;
		if (portRef.defaultLocHost == null || portRef.defaultLocHost.isEmpty()) {
			if (def_addr_family == AF_INET6) {
				def_loc_host = IPL4_IPV6_ANY_ADDR;
			} else {
				def_loc_host = IPL4_IPV4_ANY_ADDR;
			}
		} else {
			def_loc_host = portRef.defaultLocHost;
		}
		IPL4_PORTREF_DEBUG(portRef, "SetLocalSockAddr: locName: %s loc_port %d def_loc_host %s, add_family %s", locName, locPort, def_loc_host, def_addr_family == AF_INET6 ? "AF_INET6" : "AF_INET");

		if (locPort != -1 && !locName_empty) {
			localAddr = setSockAddr(locName, locPort);
		} else if (locPort == -1 && locName_empty) {
			// use default host and port
			IPL4_PORTREF_DEBUG(portRef, "%s: use defaults: %s:%d", debug_str, def_loc_host, portRef.defaultLocPort);
			localAddr = setSockAddr(def_loc_host, portRef.defaultLocPort);
		} else if (locPort == -1) {
			IPL4_PORTREF_DEBUG(portRef, "%s: use default port: %s:%d", debug_str, locName, portRef.defaultLocPort);
			localAddr = setSockAddr(locName, portRef.defaultLocPort);
		} else {
			// use default host
			IPL4_PORTREF_DEBUG(portRef, "%s: use default host: %s:%d", debug_str, def_loc_host, locPort);
			localAddr = setSockAddr(def_loc_host, locPort);
		}
		return localAddr;
	}

	public IPL4__IPAddressType GetSocketAddressType(final SelectableChannel socket) {
		//TCP
		if (socket instanceof SocketChannel) {
			InetAddress addr = ((SocketChannel) socket).socket().getLocalAddress();
			return (addr instanceof Inet4Address) ? new IPL4__IPAddressType(IPL4__IPAddressType.enum_type.IPv4) : new IPL4__IPAddressType(IPL4__IPAddressType.enum_type.IPv6);
			//TCP_LISTEN
		} else if (socket instanceof ServerSocketChannel) {
			InetAddress addr = ((ServerSocketChannel) socket).socket().getInetAddress();
			return (addr instanceof Inet4Address) ? new IPL4__IPAddressType(IPL4__IPAddressType.enum_type.IPv4) : new IPL4__IPAddressType(IPL4__IPAddressType.enum_type.IPv6);
			//UDP
		} else if (socket instanceof DatagramChannel) {
			InetAddress addr = ((DatagramChannel) socket).socket().getLocalAddress();
			return (addr instanceof Inet4Address) ? new IPL4__IPAddressType(IPL4__IPAddressType.enum_type.IPv4) : new IPL4__IPAddressType(IPL4__IPAddressType.enum_type.IPv6);
		}
		//TODO: implement sctp, ssl
		return new IPL4__IPAddressType(IPL4__IPAddressType.enum_type.ErrorReadingAddress);
	}

	private boolean setOptions(final OptionList options, final SelectableChannel sock, final ProtoTuple proto,
			boolean beforeBind) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.setOptions: enter, number of options: %d", options.size_of().get_int());
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.setOptions: sock: %s", sock.toString());
		boolean allProto = proto.get_selection() == ProtoTuple.union_selection_type.ALT_unspecified;
		boolean udpProto = proto.get_selection() == ProtoTuple.union_selection_type.ALT_udp || allProto;
		boolean tcpProto = proto.get_selection() == ProtoTuple.union_selection_type.ALT_tcp || allProto;
		boolean sslProto = proto.get_selection() == ProtoTuple.union_selection_type.ALT_ssl || allProto;
		boolean sctpProto = proto.get_selection() == ProtoTuple.union_selection_type.ALT_sctp || allProto;

		int iR = -1, iK = -1, iM = -1, iL = -1, iSSL = -1, iNoDelay = -1, iFreeBind = -1, iUDP_ENCAP = -1, iDSCP = -1,
				iMtuDiscover = -1, iS = -1;
		for (int i = 0; i < options.size_of().get_int(); i++) {
			switch (options.get_at(i).get_selection()) {
			case ALT_reuseAddress:
				iR = i;
				break;
			case ALT_tcpKeepAlive:
				iK = i;
				break;
			case ALT_sctpEventHandle:
				iM = i;
				break;
			case ALT_sslKeepAlive:
				iS = i;
				break;
			case ALT_solinger:
				iL = i;
				break;
			case ALT_ssl__support:
				iSSL = i;
				break;
			case ALT_no__delay:
				iNoDelay = i;
				break;
			case ALT_freebind:
				iFreeBind = i;
				break;
			case ALT_dtlsSrtpProfiles:
				if (sock == null) {
					if (globalConnOpts.dtlsSrtpProfiles != null || !globalConnOpts.dtlsSrtpProfiles.isEmpty()) {
						globalConnOpts.dtlsSrtpProfiles = null;
					}
					globalConnOpts.dtlsSrtpProfiles = options.get_at(i).constGet_field_dtlsSrtpProfiles().get_value().toString();
				}
				break;
			case ALT_udp__encap:
				iUDP_ENCAP = i;
				break;
			case ALT_dscp:
				iDSCP = i;
				break;
			case ALT_mtu__discover:
				iMtuDiscover = i;
				break;
			default:
				break;
			}
		}
		int enable = GlobalConnOpts.NOT_SET;

		// Process MTU Discovery for IPv6
		if (iMtuDiscover != -1) {
			int flag = -1;
			MTU__discover mtu = options.get_at(iMtuDiscover).constGet_field_mtu__discover();
			switch (mtu.enum_value) {
			case PMTUDISC__DONT:
				flag = 0;
				break;
			case PMTUDISC__WANT:
				flag = 1;
				break;
			case PMTUDISC__DO:
				flag = 2;
				break;
			default:
				TtcnError.TtcnWarning(String.format("f__IPL4__PROVIDER__setOptions: MTU option for MTU_DISCOVER is read only! On socket %s", sock.toString()));
				break;
			}

			if (flag != -1) {
				IPL4__IPAddressType type = GetSocketAddressType(sock);

				if (type.operator_not_equals(IPL4__IPAddressType.enum_type.ErrorReadingAddress)) {
					TtcnError.TtcnWarning("f__IPL4__PROVIDER__setOptions: SocketOption MTU_DISCOVER not supported in Java!");
				}
			} else {
				TtcnError.TtcnWarning("f__IPL4__PROVIDER__setOptions: error reading socket address!");
			}
		}

		// Process FREEBIND
		if (iFreeBind != -1 && sock != null) {
			globalConnOpts.freebind = options.get_at(iFreeBind).constGet_field_freebind().get_value() ? GlobalConnOpts.YES : GlobalConnOpts.NO;
		}

		// Set the FREEBIND option
		if (sock != null && beforeBind && (iFreeBind != -1 || globalConnOpts.freebind != GlobalConnOpts.NOT_SET)) {
			TtcnError.TtcnWarning("The IP option IP_FREEBIND is not supported by Java.");
		}

		// TCP/SSL/SCTP: set no delay option
		int no_delay_mode = GlobalConnOpts.NOT_SET;
		if (iNoDelay != -1) {
			if (sock == null) {
				if (!tcpProto && !sctpProto && !sslProto) {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.setOptions: Unsupported protocol for NO_DELAY");
					return false;
				}
				if (options.get_at(iNoDelay).constGet_field_no__delay().get_value()) {
					enable = GlobalConnOpts.YES;
				} else {
					enable = GlobalConnOpts.NO;
				}
				if (tcpProto) {
					globalConnOpts.tcp_nodelay = enable;
				}
				if (sctpProto) {
					globalConnOpts.sctp_nodelay = enable;
				}
			} else {
				if (options.get_at(iNoDelay).constGet_field_no__delay().get_value()) {
					no_delay_mode = GlobalConnOpts.YES;
				} else {
					no_delay_mode = GlobalConnOpts.NO;
				}
			}

		}
		if (no_delay_mode == GlobalConnOpts.NOT_SET && sock != null) {
			if (tcpProto) {
				no_delay_mode = globalConnOpts.tcp_nodelay;
			}
			if (sctpProto) {
				no_delay_mode = globalConnOpts.sctp_nodelay;
			}
		}

		if (no_delay_mode != GlobalConnOpts.NOT_SET && sock != null) {
			int flag = no_delay_mode == GlobalConnOpts.YES ? 1 : 0;
			if (USE_SCTP) {
				if (sctpProto) {
					// TODO: implement sctp layer
				}
			}
			// TCP,SSL
			if (sock instanceof SocketChannel) {
				try {
					((SocketChannel) sock).setOption(StandardSocketOptions.TCP_NODELAY, flag == 1 ? true : false);
				} catch (IOException e) {
					IPL4_DEBUG("f__IPL4__PROVIDER__setOptions: setsockopt TCP_NODELAY on socket %s failed: %s",
							sock.toString(), e.getMessage());
					return false;
				}
			}
			if (sock instanceof ServerSocketChannel) {
				try {
					((ServerSocketChannel) sock).setOption(StandardSocketOptions.TCP_NODELAY, flag == 1 ? true : false);
				} catch (IOException e) {
					IPL4_DEBUG("f__IPL4__PROVIDER__setOptions: setsockopt TCP_NODELAY on socket %s failed: %s", sock.toString(), e.getMessage());
					return false;
				}
			}
			IPL4_DEBUG("IPL4asp__PT_PROVIDER::setOptions: TCP option TCP_NODELAY on socket %s is set to: %d", sock.toString(), flag);
		}

		/* Supported SSL protocols */
		if (sock == null && iSSL != -1) {
			final SSL__proto__support sp = options.get_at(iSSL).constGet_field_ssl__support();
			for (int i = 0; i < sp.size_of().get_int(); i++) {
				switch (sp.get_at(i).get_selection()) {
				case ALT_SSLv2__supported:
					globalConnOpts.ssl_supp.SSLv2 = sp.get_at(i).get_field_SSLv2__supported().get_value() == true ? GlobalConnOpts.YES : GlobalConnOpts.NO;
					break;
				case ALT_SSLv3__supported:
					globalConnOpts.ssl_supp.SSLv3 = sp.get_at(i).get_field_SSLv3__supported().get_value() == true ? GlobalConnOpts.YES : GlobalConnOpts.NO;
					break;
				case ALT_TLSv1__supported:
					globalConnOpts.ssl_supp.TLSv1 = sp.get_at(i).get_field_TLSv1__supported().get_value() == true ? GlobalConnOpts.YES : GlobalConnOpts.NO;
					break;
				case ALT_TLSv1__1__supported:
					globalConnOpts.ssl_supp.TLSv1_1 = sp.get_at(i).get_field_TLSv1__1__supported().get_value() == true ? GlobalConnOpts.YES : GlobalConnOpts.NO;
					break;
				case ALT_TLSv1__2__supported:
					globalConnOpts.ssl_supp.TLSv1_2 = sp.get_at(i).get_field_TLSv1__2__supported().get_value() == true ? GlobalConnOpts.YES : GlobalConnOpts.NO;
					break;
				case ALT_DTLSv1__supported:
					globalConnOpts.ssl_supp.DTLSv1 = sp.get_at(i).get_field_DTLSv1__supported().get_value() == true ? GlobalConnOpts.YES : GlobalConnOpts.NO;
					break;
				case ALT_DTLSv1__2__supported:
					globalConnOpts.ssl_supp.DTLSv1_2 = sp.get_at(i).get_field_DTLSv1__2__supported().get_value() == true ? GlobalConnOpts.YES : GlobalConnOpts.NO;
					break;
				default:
					break;
				}
			}
		}

		/* set SO_LINGER */
		if (sock != null && iL != -1 && (tcpProto || sctpProto)) {

			int l_onoff = options.get_at(iL).constGet_field_solinger().constGet_field_l__onoff().get_int();
			int l_linger = options.get_at(iL).constGet_field_solinger().constGet_field_l__linger().get_int();
			if (l_onoff != 0) {
				// TCP
				if (sock instanceof SocketChannel) {
					try {
						((SocketChannel) sock).setOption(StandardSocketOptions.SO_LINGER, l_linger);
					} catch (IOException e) {
						IPL4_DEBUG("f__IPL4__PROVIDER__setOptions: setsockopt SO_LINGER on socket %s failed: %s",
								sock.toString(), e.getMessage());
						return false;
					}
				}
				if (sock instanceof ServerSocketChannel) {
					try {
						((ServerSocketChannel) sock).setOption(StandardSocketOptions.SO_LINGER, l_linger);
					} catch (IOException e) {
						IPL4_DEBUG("f__IPL4__PROVIDER__setOptions: setsockopt SO_LINGER on socket %s failed: %s",
								sock.toString(), e.getMessage());
						return false;
					}
				}
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.setOptions: TCP option SO_LINGER on socket %s is set to: enabled: %d, value %d", sock.toString(), l_onoff, l_linger);
				// TODO: implement SCTP and SSL
			}
		} else if (iL != -1) {
			IPL4_DEBUG("f__IPL4__PROVIDER__setOptions: SO_LINGER called for not connected TCP or SCTP socket ");
			return false;
		}

		/* Setting reuse address */
		enable = GlobalConnOpts.NOT_SET;
		if (iR != -1) {
			if (!tcpProto && !udpProto && !sctpProto && !sslProto) {
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.setOptions: Unsupported protocol for reuse address");
				return false;
			}
			enable = GlobalConnOpts.YES;
			if (options.get_at(iR).constGet_field_reuseAddress().constGet_field_enable().is_present() && options.get_at(iR).constGet_field_reuseAddress().constGet_field_enable().get().get_value() == false) {
				enable = GlobalConnOpts.NO;
			}
			if (sock == null) {
				if (tcpProto) {
					globalConnOpts.tcpReuseAddr = enable;
				}
				if (udpProto) {
					globalConnOpts.udpReuseAddr = enable;
				}
				if (sctpProto) {
					globalConnOpts.sctpReuseAddr = enable;
				}
				if (sslProto) {
					globalConnOpts.sctpReuseAddr = enable;
				}
			}
		}
		if (sock != null && (iR != -1 || beforeBind)) {
			if (enable == GlobalConnOpts.NOT_SET) {
				if (allProto) {
					return false;
				}
				if (tcpProto) {
					enable = globalConnOpts.tcpReuseAddr;
				} else if (udpProto) {
					enable = globalConnOpts.udpReuseAddr;
				} else if (sctpProto) {
					enable = globalConnOpts.sctpReuseAddr;
				} else if (sslProto) {
					enable = globalConnOpts.sslReuseAddr;
				}
			}
			if (enable == GlobalConnOpts.YES) {
				boolean reuseAddress = true;
				// TCP
				if (sock instanceof SocketChannel) {
					try {
						((SocketChannel) sock).setOption(StandardSocketOptions.SO_REUSEADDR, reuseAddress);
					} catch (IOException e) {
						IPL4_DEBUG("f__IPL4__PROVIDER__setOptions: setsockopt REUSEADDR on socket %s failed: %s", sock.toString(), e.getMessage());
						return false;
					}
				}
				if (sock instanceof ServerSocketChannel) {
					try {
						((ServerSocketChannel) sock).setOption(StandardSocketOptions.SO_REUSEADDR, reuseAddress);
					} catch (IOException e) {
						IPL4_DEBUG("f__IPL4__PROVIDER__setOptions: setsockopt REUSEADDR on socket %s failed: %s", sock.toString(), e.getMessage());
						return false;
					}
				}
				// UDP
				if (sock instanceof DatagramChannel) {
					try {
						((DatagramChannel) sock).setOption(StandardSocketOptions.SO_REUSEADDR, reuseAddress);
					} catch (IOException e) {
						IPL4_DEBUG("f__IPL4__PROVIDER__setOptions: setsockopt REUSEADDR on socket %s failed: %s", sock.toString(), e.getMessage());
						return false;
					}
				}
				// TODO: implement SCTP and SSL
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.setOptions: Socket option REUSEADDR on socket %s is set to: %s", sock.toString(), reuseAddress);
			}
		}

		/* Set broadcast for UDP */
		if (sock != null && udpProto) {
			if (broadcast) {
				boolean on = true;
				if (sock instanceof DatagramChannel) {
					try {
						((DatagramChannel) sock).setOption(StandardSocketOptions.SO_BROADCAST, on);
					} catch (IOException e) {
						throw new TtcnError("Setsockopt error: SO_BROADCAST");
					}
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.sendNonBlocking: Socket option SO_BROADCAST on ");
				}
			}
		}

		/* set UDP_ENCAP */
		if (sock != null && iUDP_ENCAP != -1 && udpProto) {
			IPL4_DEBUG("f__IPL4__PROVIDER__setOptions: UDP_ENCAP not supported on Java");
			return false;
		}

		/* Setting keep alive TCP */
		if (iK != -1 && !tcpProto) {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.setOptions: Unsupported protocol for tcp keep alive");
			return false;
		}
		if (tcpProto) {
			enable = globalConnOpts.tcpKeepAlive;
			int count = globalConnOpts.tcpKeepCnt;
			int idle = globalConnOpts.tcpKeepIdle;
			int interval = globalConnOpts.tcpKeepIntvl;
			if (iK != -1) {
				if (options.get_at(iK).constGet_field_tcpKeepAlive().constGet_field_enable().is_present()) {
					enable = GlobalConnOpts.NO;
					if (options.get_at(iK).constGet_field_tcpKeepAlive().constGet_field_enable().get()
							.get_value() == true) {
						enable = GlobalConnOpts.YES;
					}
				}
				if (options.get_at(iK).constGet_field_tcpKeepAlive().constGet_field_count().ispresent()) {
					count = options.get_at(iK).constGet_field_tcpKeepAlive().constGet_field_count().get().get_int();
				}
				if (options.get_at(iK).constGet_field_tcpKeepAlive().constGet_field_idle().ispresent()) {
					idle = options.get_at(iK).constGet_field_tcpKeepAlive().constGet_field_idle().get().get_int();
				}
				if (options.get_at(iK).constGet_field_tcpKeepAlive().constGet_field_interval().ispresent()) {
					interval = options.get_at(iK).constGet_field_tcpKeepAlive().constGet_field_interval().get().get_int();
				}

				if (count < 0 || idle < 0 || interval < 0) {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.setOptions: Invalid tcp keep alive parameter.");
					return false;
				}
				if (sock == null) {
					globalConnOpts.tcpKeepAlive = enable;
					globalConnOpts.tcpKeepCnt = count;
					globalConnOpts.tcpKeepIdle = idle;
					globalConnOpts.tcpKeepIntvl = interval;
				}
			}
			if (sock != null && (iK != -1 || beforeBind)) {
				IPL4_DEBUG("f__IPL4__PROVIDER__connect: setsockopt TCP_KEEPCNT on socket %s failed: Java not supported TCP_KEEPCNT socket option.", sock.toString());

				IPL4_DEBUG("f__IPL4__PROVIDER__connect: setsockopt TCP_KEEPIDLE on socket %s failed: Java not supported TCP_KEEPIDLE socket option.", sock.toString());

				IPL4_DEBUG("f__IPL4__PROVIDER__connect: setsockopt TCP_KEEPINTVL on socket %s failed: Java not supported TCP_KEEPINTVL socket option.", sock.toString());

				if (enable != GlobalConnOpts.NOT_SET) {
					boolean keepAlive = (enable == GlobalConnOpts.YES) ? true : false;
					if (sock instanceof SocketChannel) {
						try {
							((SocketChannel) sock).setOption(StandardSocketOptions.SO_KEEPALIVE, keepAlive);
						} catch (IOException e) {
							IPL4_DEBUG("f__IPL4__PROVIDER__setOptions: setsockopt SO_KEEPALIVE on socket %s failed: %s", sock.toString(), e.getMessage());
							return false;
						}
					}
					if (sock instanceof ServerSocketChannel) {
						try {
							((ServerSocketChannel) sock).setOption(StandardSocketOptions.SO_KEEPALIVE, keepAlive);
						} catch (IOException e) {
							IPL4_DEBUG("f__IPL4__PROVIDER__setOptions: setsockopt SO_KEEPALIVE on socket %s failed: %s", sock.toString(), e.getMessage());
							return false;
						}
					}
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.setOptions: socket option SO_KEEPALIVE on socket %s is set to: %s", sock.toString(), keepAlive);
				}
			}
		}
		// TODO: SSL keep-alive option
		// TODO: SCTP events and inits

		int dscp = globalConnOpts.dscp;
		if (iDSCP != -1) {
			// Store the dscp option
			dscp = options.get_at(iDSCP).constGet_field_dscp().get_int();
			globalConnOpts.dscp = dscp;
		}
		set_dscp_option(sock);

		IPL4_DEBUG("IPL4asp__PT_PROVIDER.setOptions: leave");
		return true;
	}

	//Returns the currently active option for the given socket. Return -1, if the request could not be completed
	private int getOption(final Option option, SelectableChannel sock, final ProtoTuple proto, boolean beforeBind) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.getOption: enter, sock: %s", sock.toString());

		IPL4_DEBUG("IPL4asp__PT_PROVIDER.getOption: not finished! Return 0");
		return 0;
	}

	private void set_dscp_option(SelectableChannel sock) {
		if (sock != null && (globalConnOpts.dscp != GlobalConnOpts.NOT_SET)) {
			int dscp = globalConnOpts.dscp << 2;
			// Don't need to store IP Address Type
			if (GetSocketAddressType(sock).enum_value != IPL4__IPAddressType.enum_type.ErrorReadingAddress) {
				// TCP
				if (sock instanceof SocketChannel) {
					try {
						((SocketChannel) sock).socket().setOption(StandardSocketOptions.IP_TOS, dscp);
					} catch (IOException e) {
						TtcnError.TtcnWarning(String.format("IPL4asp__PT_PROVIDER.set_dscp_option: setsockopt DSCP to %d on socket %s failed: %s", globalConnOpts.dscp, sock.toString(), e.getMessage()));
					}
				}
				// UDP
				if (sock instanceof DatagramChannel) {
					try {
						// TODO: Java 8
						((DatagramChannel) sock).socket().setOption(StandardSocketOptions.IP_TOS, dscp);
					} catch (IOException e) {
						TtcnError.TtcnWarning(String.format("IPL4asp__PT_PROVIDER.set_dscp_option: setsockopt DSCP to %d on socket %s failed: %s", globalConnOpts.dscp, sock.toString(), e.getMessage()));
					}
				}
				// TODO: implement SCTP and SSL
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.set_dscp_option: DSCP on socket %s is set to value %d", sock.toString(), globalConnOpts.dscp);
			}
		}
	}

	private void testIfInitialized() {
		if (!mapped) {
			throw new TtcnError("IPL4 Test Port not mapped");
		}
	}

	private void setResult(Result result, PortError code, final TitanInteger id, int os_error_code) {
		result.get_field_errorCode().get().operator_assign(code);
		result.get_field_connId().get().operator_assign(id);
		if (os_error_code != 0) {
			result.get_field_os__error__code().get().operator_assign(os_error_code);
			//FIXME: error text
			result.get_field_os__error__text().operator_assign(template_sel.OMIT_VALUE);
		} else {
			result.get_field_os__error__code().operator_assign(template_sel.OMIT_VALUE);
			result.get_field_os__error__text().operator_assign(template_sel.OMIT_VALUE);
		}
	}

	private void setResult(Result result, PortError code, final TitanInteger id) {
		result.get_field_errorCode().get().operator_assign(code);
		result.get_field_connId().get().operator_assign(id);
		result.get_field_os__error__code().operator_assign(template_sel.OMIT_VALUE);
		result.get_field_os__error__text().operator_assign(template_sel.OMIT_VALUE);
	}

	private int ConnDel(final int connId, final boolean forced) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnDel: enter: connId: %d", connId);
		SelectableChannel sock = sockList.get(connId).sock;
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnDel: socket: %s", sock != null ? sock.toString() : "null");
		if (sock == null) {
			return -1;
		}
		// TODO: Handler_Remove_Fd(sock, EVENT_ALL)

		try {
			TTCN_Snapshot.selector.get().selectNow();
			Set<SelectionKey> selectedKeys = TTCN_Snapshot.selector.get().selectedKeys();
			Iterator<SelectionKey> keyIterator = selectedKeys.iterator();
			while (keyIterator.hasNext()) {
				SelectionKey selectionKey = keyIterator.next();
				if (selectionKey.channel().equals(sock)) {
					selectionKey.cancel();
				}
				keyIterator.remove();
			}
			TTCN_Snapshot.channelMap.get().remove(sock);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		if (IPL4_USE_SSL) {
			if ((sockList.get(connId).ssl_tls_type != SSL_TLS_Type.NONE) && (sockList.get(connId).type != SockType.IPL4asp_SCTP_LISTEN) && (sockList.get(connId).type != SockType.IPL4asp_TCP_LISTEN) && mapped) {
				// TODO: perform_ssl_shutdown(connId);
			}
			sockList.get(connId).sctpHandshakeCompletedBeforeDtls = false;
		}
		try {
			if (sock.isOpen()) {
				sock.close();
			}
		} catch (IOException e) {
			TtcnError.TtcnWarning(String.format("IPL4asp__PT_PROVIDER.ConnDel: failed to close socket %s: %s, connId: %d", sock != null ? sock.toString() : "null", e.getMessage(), connId));
		}
		sockList.get(connId).clear();
		if (!connId_release_confirmed || forced) {
			//No need to implement ConnFree function. Just decrease the size or call Map.size()
			sockListCnt--;
			sockListSize = sockList.size();
		} else {
			incoming_message(new ASP__ConnId__ReadyToRelease(new TitanInteger(connId)));
		}
		return connId;
	}

	private int ConnAdd(SockType type, SelectableChannel sock, SSL_TLS_Type ssl_tls_type, final IPL4asp__Types.OptionList options, int parentIdx) {
		//FIXME: Instead of type name use ordinal (optional)
		IPL4_DEBUG("IPL4asp__PT_PROVIDER: ConnAdd enter: type: %s, ssl_tls_type: %s, sock: %s, parentIx: %d", type.name(), ssl_tls_type.name(), sock.toString(), parentIdx);
		testIfInitialized();

		int i = sock.hashCode();
		SockDesc socketDesc = new SockDesc();
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnAdd: connId: %d", i);

		if (parentIdx != -1) { // inherit the listener's properties
			// TODO:
			if (sockList.containsKey(i)) {
				SockDesc parent = sockList.get(i);
				socketDesc.userData = parent.userData;
				socketDesc.getMsgLen = parent.getMsgLen;
				socketDesc.getMsgLen_forConnClosedEvent = parent.getMsgLen_forConnClosedEvent;
				socketDesc.parentIdx = parentIdx;
				socketDesc.msgLenArgs = new Socket__API__Definitions.ro__integer(parent.msgLenArgs);
				socketDesc.msgLenArgs_forConnClosedEvent = new Socket__API__Definitions.ro__integer(parent.msgLenArgs_forConnClosedEvent);
				socketDesc.ssl_supp.SSLv2 = parent.ssl_supp.SSLv2;
				socketDesc.ssl_supp.SSLv3 = parent.ssl_supp.SSLv3;
				socketDesc.ssl_supp.TLSv1 = parent.ssl_supp.TLSv1;
				socketDesc.ssl_supp.TLSv1_1 = parent.ssl_supp.TLSv1_1;
				socketDesc.ssl_supp.TLSv1_2 = parent.ssl_supp.TLSv1_2;
				socketDesc.ssl_supp.DTLSv1 = parent.ssl_supp.DTLSv1;
				socketDesc.ssl_supp.DTLSv1_2 = parent.ssl_supp.DTLSv1_2;
				if (parent.dtlsSrtpProfiles != null) {
					socketDesc.dtlsSrtpProfiles = parent.dtlsSrtpProfiles;
				} else {
					socketDesc.dtlsSrtpProfiles = null;
				}
				if (parent.ssl_key_file != null) {
					socketDesc.ssl_key_file = parent.ssl_key_file;
				} else {
					socketDesc.ssl_key_file = null;
				}
				if (parent.ssl_certificate_file != null) {
					socketDesc.ssl_certificate_file = parent.ssl_certificate_file;
				} else {
					socketDesc.ssl_certificate_file = null;
				}
				if (parent.ssl_cipher_list != null) {
					socketDesc.ssl_cipher_list = parent.ssl_cipher_list;
				} else {
					socketDesc.ssl_cipher_list = null;
				}
				if (parent.ssl_trustedCAlist_file != null) {
					socketDesc.ssl_trustedCAlist_file = parent.ssl_trustedCAlist_file;
				} else {
					socketDesc.ssl_trustedCAlist_file = null;
				}
				if (parent.ssl_password != null) {
					socketDesc.ssl_password = parent.ssl_password;
				} else {
					socketDesc.ssl_password = null;
				}
				if (parent.psk_identity != null) {
					socketDesc.psk_identity = parent.psk_identity;
				} else {
					socketDesc.psk_identity = null;
				}
				if (parent.psk_identity_hint != null) {
					socketDesc.psk_identity_hint = parent.psk_identity_hint;
				} else {
					socketDesc.psk_identity_hint = null;
				}
				if (parent.psk_key != null) {
					socketDesc.psk_key = parent.psk_key;
				} else {
					socketDesc.psk_key = null;
				}

				if (parent.tls_hostname != null) {
					socketDesc.tls_hostname = new TitanCharString(parent.tls_hostname);
				} else {
					socketDesc.tls_hostname = null;
				}
				if (parent.alpn != null) {
					socketDesc.alpn = new TitanOctetString(parent.alpn);
				} else {
					socketDesc.alpn = null;
				}
			} else {
				socketDesc.userData = 0;
				socketDesc.parentIdx = -1;
				socketDesc.msgLenArgs = new Socket__API__Definitions.ro__integer(defaultMsgLenArgs);
				socketDesc.msgLenArgs_forConnClosedEvent = new Socket__API__Definitions.ro__integer(defaultMsgLenArgs_forConnClosedEvent);
				socketDesc.ssl_supp.SSLv2 = globalConnOpts.ssl_supp.SSLv2;
				socketDesc.ssl_supp.SSLv3 = globalConnOpts.ssl_supp.SSLv3;
				socketDesc.ssl_supp.TLSv1 = globalConnOpts.ssl_supp.TLSv1;
				socketDesc.ssl_supp.TLSv1_1 = globalConnOpts.ssl_supp.TLSv1_1;
				socketDesc.ssl_supp.TLSv1_2 = globalConnOpts.ssl_supp.TLSv1_2;
				socketDesc.ssl_supp.DTLSv1 = globalConnOpts.ssl_supp.DTLSv1;
				socketDesc.ssl_supp.DTLSv1_2 = globalConnOpts.ssl_supp.DTLSv1_2;
				socketDesc.dtlsSrtpProfiles = null;
				socketDesc.ssl_key_file = null;
				socketDesc.ssl_certificate_file = null;
				socketDesc.ssl_trustedCAlist_file = null;
				socketDesc.ssl_cipher_list = null;
				socketDesc.ssl_password = null;
				socketDesc.tls_hostname = null;
				socketDesc.alpn = null;
				socketDesc.psk_identity = null;
				socketDesc.psk_identity_hint = null;
				socketDesc.psk_key = null;
			}
		} else {
			socketDesc.userData = 0;
			socketDesc.parentIdx = -1;
			socketDesc.msgLenArgs = new Socket__API__Definitions.ro__integer(TitanNull_Type.NULL_VALUE);
			socketDesc.msgLenArgs_forConnClosedEvent = new Socket__API__Definitions.ro__integer(TitanNull_Type.NULL_VALUE);
			socketDesc.ssl_supp = new SSL_Support();
			socketDesc.ssl_supp.SSLv2 = globalConnOpts.ssl_supp.SSLv2;
			socketDesc.ssl_supp.SSLv3 = globalConnOpts.ssl_supp.SSLv3;
			socketDesc.ssl_supp.TLSv1 = globalConnOpts.ssl_supp.TLSv1;
			socketDesc.ssl_supp.TLSv1_1 = globalConnOpts.ssl_supp.TLSv1_1;
			socketDesc.ssl_supp.TLSv1_2 = globalConnOpts.ssl_supp.TLSv1_2;
			socketDesc.ssl_supp.DTLSv1 = globalConnOpts.ssl_supp.DTLSv1;
			socketDesc.ssl_supp.DTLSv1_2 = globalConnOpts.ssl_supp.DTLSv1_2;
			socketDesc.dtlsSrtpProfiles = null;
			socketDesc.ssl_key_file = null;
			socketDesc.ssl_certificate_file = null;
			socketDesc.ssl_trustedCAlist_file = null;
			socketDesc.ssl_cipher_list = null;
			socketDesc.ssl_password = null;
			socketDesc.tls_hostname = null;
			socketDesc.alpn = null;
			socketDesc.psk_identity = null;
			socketDesc.psk_identity_hint = null;
			socketDesc.psk_key = null;
			if (options != null) {
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnAdd: connId: set ssl options for connId : %d", i);
				// TODO:implement set_ssl_supp_option(i, options);
			}
		}
		socketDesc.msgLen = -1;
		socketDesc.type = type;
		socketDesc.ssl_tls_type = ssl_tls_type;
		socketDesc.localaddr = new TitanCharString("");
		socketDesc.localport = new TitanInteger(-1);

		if (IPL4_USE_SSL) {
			socketDesc.sslCTX = null;
		}

		socketDesc.sctpHandshakeCompletedBeforeDtls = false;

		//TCP
		if (sock instanceof SocketChannel) {
			socketDesc.localaddr = new TitanCharString(((SocketChannel) sock).socket().getLocalAddress().toString());
			socketDesc.localport = new TitanInteger(((SocketChannel) sock).socket().getLocalPort());
		}

		//TCP_Listen
		if (sock instanceof ServerSocketChannel) {
			socketDesc.localaddr = new TitanCharString(((ServerSocketChannel) sock).socket().getLocalSocketAddress().toString());
			socketDesc.localport = new TitanInteger(((ServerSocketChannel) sock).socket().getLocalPort());
		}

		//UDP
		if (sock instanceof DatagramChannel) {
			socketDesc.localaddr = new TitanCharString(((DatagramChannel) sock).socket().getLocalAddress().toString());
			socketDesc.localport = new TitanInteger(((DatagramChannel) sock).socket().getLocalPort());
		}
		// TODO: implement sctp,ssl

		socketDesc.buf = null;
		socketDesc.assocIdList = 0;
		socketDesc.cnt = 0;

		switch (type) {
		case IPL4asp_TCP_LISTEN:
		case IPL4asp_SCTP_LISTEN:
			break;
		case IPL4asp_UDP:
		case IPL4asp_TCP:
		case IPL4asp_SCTP:
			socketDesc.buf = new TTCN_Buffer();
			if (socketDesc.buf == null) {
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnAdd: failed to add socket %s", sock.toString());
				return -1;
			}
			if (type == SockType.IPL4asp_TCP) {
				socketDesc.assocIdList = 0;
			} else {
				// IPL4asp_SCTP
				socketDesc.assocIdList = 0;
			}
			socketDesc.cnt = 1;
			if (sock instanceof SocketChannel) {
				try {
					if (((SocketChannel) sock).getRemoteAddress() == null) {
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnAdd: getRemoteAddress failed: Transport endpoint is not connected");
					} else {
						socketDesc.remoteaddr = new TitanCharString(((SocketChannel) sock).socket().getInetAddress().toString());
						socketDesc.remoteport = new TitanInteger(((SocketChannel) sock).socket().getPort());
					}
				} catch (IOException e) {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnAdd: getRemoteAddress failed: %s", e.getMessage());
				}
			}
			if (sock instanceof DatagramChannel) {
				try {
					if (((DatagramChannel) sock).getRemoteAddress() == null) {
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnAdd: getRemoteAddress failed: Transport endpoint is not connected");
					} else {
						socketDesc.remoteaddr = new TitanCharString(((DatagramChannel) sock).socket().getInetAddress().toString());
						socketDesc.remoteport = new TitanInteger(((DatagramChannel) sock).socket().getPort());
					}
				} catch (IOException e) {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnAdd: getRemoteAddress failed: %s", e.getMessage());
				}
			}
			// TODO: implement sctp,ssl
			break;
		default:
			break;
		}

		switch (ssl_tls_type) {
		case NONE:
			// nothing to be done
			break;
		case SERVER:
			socketDesc.sslState = SSL_STATES.STATE_NORMAL;
			break;
		case CLIENT:
			socketDesc.sslState = SSL_STATES.STATE_CONNECTING;
			socketDesc.server = false;
			break;
		default:
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnAdd: unhandled SSL/TLS type");
			// TODO: sendError(PortError::ERROR__GENERAL, i);
			break;
		}

		try {
			IPL4_DEBUG(sock.toString());
			if (sock instanceof ServerSocketChannel) {
				TTCN_Snapshot.channelMap.get().put(sock, this);
				sock.register(TTCN_Snapshot.selector.get(), SelectionKey.OP_ACCEPT);
				TTCN_Snapshot.set_timer(this, 0.0, true, true, true);
			} else {
				Install_Handler(Set.of(sock), null, 0.0);
			}
		} catch (IOException e) {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnAdd: Error on Handler_Add_Fd_Read: %s", e.getMessage());
		}
		socketDesc.sock = sock;
		sockList.put(i, socketDesc);
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.ConnAdd: leave: sockListCnt: %d", sockList.size());

		return i;
	}

	private int setUserData(int connId, int userData) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.setUserData enter: connId %d userdata %d", connId, userData);
		testIfInitialized();
		if (!isConnIdValid(connId)) {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.setUserData: invalid connId: %d", connId);
			return -1;
		}
		sockList.get(connId).userData = userData;
		return connId;
	}

	private int getUserData(int connId, int userData) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.getUserData enter: socket %d", connId);
		testIfInitialized();
		if (!isConnIdValid(connId)) {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.getUserData: invalid connId: %d", connId);
			return -1;
		}
		userData = sockList.get(connId).userData;
		return connId;
	}

	private int getConnectionDetails(final int connId, IPL4__Param IPL4param, IPL4__ParamResult IPL4paramResult) {
		IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails enter: socket %d", connId);
		testIfInitialized();
		if (!isConnIdValid(connId)) {
			IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails: invalid connId: %d", connId);
			return -1;
		}
		SocketAddress sa = null;
		SockType type = null;
		switch (IPL4param.enum_value) {
		case IPL4__LOCALADDRESS:
			//TCP
			if (sockList.get(connId).sock instanceof SocketChannel) {
				try {
					if (((SocketChannel) (sockList.get(connId).sock)).getLocalAddress() == null) {
						IPL4paramResult.get_field_local().get_field_hostName().operator_assign("?");
						IPL4paramResult.constGet_field_local().get_field_portNumber().operator_assign(-1);
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails: getLocalAddress returned with null");
						return -1;
					} else {
						IPL4paramResult.get_field_local().get_field_hostName().operator_assign(((SocketChannel) (sockList.get(connId).sock)).socket().getLocalAddress().toString());
						IPL4paramResult.constGet_field_local().get_field_portNumber().operator_assign(((SocketChannel) (sockList.get(connId).sock)).socket().getLocalPort());
					}
				} catch (IOException e) {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails: getLocalAddress error: %s", e.getMessage());
					return -1;
				}
			}
			//TCP_LISTEN
			if (sockList.get(connId).sock instanceof ServerSocketChannel) {
				try {
					if (((ServerSocketChannel) (sockList.get(connId).sock)).getLocalAddress() == null) {
						IPL4paramResult.get_field_local().get_field_hostName().operator_assign("?");
						IPL4paramResult.constGet_field_local().get_field_portNumber().operator_assign(-1);
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails: getLocalAddress returned with null");
						return -1;
					} else {
						IPL4paramResult.get_field_local().get_field_hostName().operator_assign(((ServerSocketChannel) (sockList.get(connId).sock)).socket().getLocalSocketAddress().toString());
						IPL4paramResult.constGet_field_local().get_field_portNumber().operator_assign(((ServerSocketChannel) (sockList.get(connId).sock)).socket().getLocalPort());
					}
				} catch (IOException e) {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails: getLocalAddress error: %s", e.getMessage());
					return -1;
				}
			}
			//UDP
			if (sockList.get(connId).sock instanceof DatagramChannel) {
				try {
					if (((DatagramChannel) (sockList.get(connId).sock)).getLocalAddress() == null) {
						IPL4paramResult.get_field_local().get_field_hostName().operator_assign("?");
						IPL4paramResult.constGet_field_local().get_field_portNumber().operator_assign(-1);
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails: getLocalAddress returned with null");
						return -1;
					} else {
						IPL4paramResult.get_field_local().get_field_hostName().operator_assign(((DatagramChannel) (sockList.get(connId).sock)).socket().getLocalAddress().toString());
						IPL4paramResult.constGet_field_local().get_field_portNumber().operator_assign(((DatagramChannel) (sockList.get(connId).sock)).socket().getLocalPort());
					}
				} catch (IOException e) {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails: getLocalAddress error: %s", e.getMessage());
					return -1;
				}
			}
			//TODO: implement SSL, SCTP
			break;
		case IPL4__REMOTEADDRESS:
			//TCP
			if (sockList.get(connId).sock instanceof SocketChannel) {
				try {
					if (((SocketChannel) (sockList.get(connId).sock)).getRemoteAddress() == null) {
						IPL4paramResult.get_field_local().get_field_hostName().operator_assign("?");
						IPL4paramResult.constGet_field_local().get_field_portNumber().operator_assign(-1);
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails: getRemoteAddress returned with null");
						return -1;
					} else {
						IPL4paramResult.get_field_local().get_field_hostName().operator_assign(((SocketChannel) (sockList.get(connId).sock)).socket().getInetAddress().toString());
						IPL4paramResult.constGet_field_local().get_field_portNumber().operator_assign(((SocketChannel) (sockList.get(connId).sock)).socket().getLocalPort());
					}
				} catch (IOException e) {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails: getRemoteAddress error: %s", e.getMessage());
					return -1;
				}
			}
			//TCP_LISTEN
			if (sockList.get(connId).sock instanceof ServerSocketChannel) {
				IPL4paramResult.get_field_local().get_field_hostName().operator_assign("?");
				IPL4paramResult.constGet_field_local().get_field_portNumber().operator_assign(-1);
				return -1;
			}
			//UDP
			if (sockList.get(connId).sock instanceof DatagramChannel) {
				try {
					if (((DatagramChannel) (sockList.get(connId).sock)).getRemoteAddress() == null) {
						IPL4paramResult.get_field_local().get_field_hostName().operator_assign("?");
						IPL4paramResult.constGet_field_local().get_field_portNumber().operator_assign(-1);
						IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails: getRemoteAddress returned with null");
						return -1;
					} else {
						IPL4paramResult.get_field_local().get_field_hostName().operator_assign(((DatagramChannel) (sockList.get(connId).sock)).socket().getInetAddress().toString());
						IPL4paramResult.constGet_field_local().get_field_portNumber().operator_assign(((DatagramChannel) (sockList.get(connId).sock)).socket().getLocalPort());
					}
				} catch (IOException e) {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.getConnectionDetails: getRemoteAddress error: %s", e.getMessage());
					return -1;
				}
			}
			//TODO: implement SSL, SCTP
			break;
		case IPL4__PROTO:
			type = sockList.get(connId).type;
			switch (type) {
			case IPL4asp_UDP:
				IPL4paramResult.get_field_proto().get_field_udp().operator_assign(new UdpTuple(TitanNull_Type.NULL_VALUE));
				break;
			case IPL4asp_TCP_LISTEN:
			case IPL4asp_TCP:
				if (sockList.get(connId).ssl_tls_type == SSL_TLS_Type.NONE) {
					IPL4paramResult.get_field_proto().get_field_tcp().operator_assign(new TcpTuple(TitanNull_Type.NULL_VALUE));
				} else {
					IPL4paramResult.get_field_proto().get_field_ssl().operator_assign(new SslTuple(TitanNull_Type.NULL_VALUE));
				}
				break;
			case IPL4asp_SCTP_LISTEN:
			case IPL4asp_SCTP:
				IPL4paramResult.get_field_proto().get_field_sctp().operator_assign(new SctpTuple(new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(Socket__API__Definitions.SocketList.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE)));
				break;
			default:
				break;
			}
			break;
		case IPL4__USERDATA:
			IPL4paramResult.get_field_userData().operator_assign(sockList.get(connId).userData);
			break;
		case IPL4__PARENTIDX:
			IPL4paramResult.get_field_parentIdx().operator_assign(sockList.get(connId).parentIdx);
			break;
		default:
			break;
		}

		return connId;
	}

	//FIXME: use exception or throwable type instead of int for os_error_code
	private void sendError(PortError code, final int id, int os_error_code) {
		ASP__Event event = new ASP__Event();
		event.get_field_result().get_field_errorCode().get().operator_assign(code);
		event.get_field_result().get_field_connId().get().operator_assign(id);
		if (os_error_code != 0) {
			event.get_field_result().get_field_os__error__code().get().operator_assign(os_error_code);
			event.get_field_result().get_field_os__error__text().operator_assign(template_sel.OMIT_VALUE);
		} else {
			event.get_field_result().get_field_os__error__code().operator_assign(template_sel.OMIT_VALUE);
			event.get_field_result().get_field_os__error__text().operator_assign(template_sel.OMIT_VALUE);
		}
		incoming_message(event);
	}

	private void reportRemainingData_beforeConnClosed(final TitanInteger id, final TitanCharString remoteaddr, final TitanInteger remoteport, final TitanCharString localaddr, final TitanInteger localport, final ProtoTuple proto, final int userData) {
		// check if the remaining data is to be reported to the TTCN layer
		if ((sockList.get(id.get_int()).getMsgLen_forConnClosedEvent != null) && (sockList.get(id.get_int()).buf != null)) {
			boolean msgFound = false;
			do {
				TitanOctetString oct = new TitanOctetString();
				sockList.get(id.get_int()).buf.get_string(oct);
				sockList.get(id.get_int()).msgLen = sockList.get(id.get_int()).getMsgLen_forConnClosedEvent.invoke(oct, sockList.get(id.get_int()).msgLenArgs_forConnClosedEvent).get_int();

				msgFound = (sockList.get(id.get_int()).msgLen > 0) && (sockList.get(id.get_int()).msgLen <= sockList.get(id.get_int()).buf.get_len());
				if (msgFound) {
					IPL4_DEBUG("IPL4asp__PT_PROVIDER.reportRemainingData_beforeConnClosed: message length: (%d/%d bytes)\n", sockList.get(id.get_int()).msgLen, sockList.get(id.get_int()).buf.get_len());
					ASP__RecvFrom asp = new ASP__RecvFrom();
					asp.get_field_connId().operator_assign(id);
					asp.get_field_userData().operator_assign(userData);
					asp.get_field_remName().operator_assign(remoteaddr);
					asp.get_field_remPort().operator_assign(remoteport);
					asp.get_field_locName().operator_assign(localaddr);
					asp.get_field_locPort().operator_assign(localport);
					asp.get_field_proto().operator_assign(proto);
					asp.get_field_msg().operator_assign(new TitanOctetString(sockList.get(id).buf.get_data()));
					sockList.get(id.get_int()).buf.set_pos(sockList.get(id.get_int()).msgLen);
					sockList.get(id.get_int()).buf.cut();
					if (lazy_conn_id_level != 0 && sockListCnt == 1 && lonely_conn_id != -1) {
						asp.get_field_connId().operator_assign(-1);
					}
					incoming_message(asp);
					sockList.get(id.get_int()).msgLen = -1;
				}
			} while (msgFound && sockList.get(id.get_int()).buf.get_len() != 0);
			if (sockList.get(id.get_int()).buf.get_len() != 0) {
				IPL4_DEBUG("IPL4asp__PT_PROVIDER.reportRemainingData_beforeConnClosed: incomplete message remained (%d bytes)\n", sockList.get(id.get_int()).buf.get_len());
			}
		}
	}

	private void sendConnClosed(final TitanInteger id, final TitanCharString remoteaddr, final TitanInteger remoteport, final TitanCharString localaddr, final TitanInteger localport, final Socket__API__Definitions.ProtoTuple proto, final int userData) {
		ASP__Event event_close = new ASP__Event();
		event_close.get_field_connClosed().operator_assign(new ConnectionClosedEvent());
		event_close.get_field_connClosed().get_field_connId().operator_assign(id);
		event_close.get_field_connClosed().get_field_remName().operator_assign(remoteaddr);
		event_close.get_field_connClosed().get_field_remPort().operator_assign(remoteport);
		event_close.get_field_connClosed().get_field_locName().operator_assign(localaddr);
		event_close.get_field_connClosed().get_field_locPort().operator_assign(localport);
		event_close.get_field_connClosed().get_field_proto().operator_assign(proto);
		event_close.get_field_connClosed().get_field_userData().operator_assign(userData);

		incoming_message(event_close);
	}

	public TitanInteger simpleGetMsgLen(final TitanOctetString stream, Socket__API__Definitions.ro__integer args) {
		return stream.lengthof();
	}

	public boolean isConnIdValid(final int connId) {
		return sockList != null && sockList.containsKey(connId) && sockList.get(connId).sock != null;
	}

	public boolean isConnIdReleaseWait(final int connId) {
		return sockList != null && sockList.containsKey(connId) && sockList.get(connId).sock != null && !sockList.get(connId).sock.isOpen();
	}

	protected void f__IPL4__PROVIDER__setGetMsgLen(IPL4asp__PT_PROVIDER portRef, final TitanInteger connId, f__getMsgLen f, final Socket__API__Definitions.ro__integer msgLenArgs) {
		portRef.testIfInitialized();
		if (connId.get_int() == -1) {
			portRef.defaultGetMsgLen = f;
			portRef.defaultMsgLenArgs = null;
			portRef.defaultMsgLenArgs = new Socket__API__Definitions.ro__integer(msgLenArgs);
			IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__setGetMsgLen: The default getMsgLen fn is modified");
		} else {
			if (!portRef.isConnIdValid(connId.get_int())) {
				IPL4_PORTREF_DEBUG(portRef, "IPL4asp__PT_PROVIDER.f__IPL4__PROVIDER__setGetMsgLen: invalid connId: %d", connId.get_int());
				return;
			}
			IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__setGetMsgLen: getMsgLen fn for connection %d is modified", connId.get_int());
			portRef.sockList.get(connId.get_int()).getMsgLen = f;
			portRef.sockList.get(connId.get_int()).msgLenArgs = null;
			portRef.sockList.get(connId.get_int()).msgLenArgs = new Socket__API__Definitions.ro__integer(msgLenArgs);
		}
	}

	protected void f__IPL4__PROVIDER__setGetMsgLen__forConnClosedEvent(IPL4asp__PT_PROVIDER portRef, final TitanInteger connId, f__getMsgLen f, final Socket__API__Definitions.ro__integer msgLenArgs) {
		portRef.testIfInitialized();
		if (connId.get_int() == -1) {
			portRef.defaultGetMsgLen_forConnClosedEvent = f;
			portRef.defaultMsgLenArgs_forConnClosedEvent = null;
			portRef.defaultMsgLenArgs_forConnClosedEvent = new Socket__API__Definitions.ro__integer(msgLenArgs);
			IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__setGetMsgLen_forConnClosedEvent: The default getMsgLen_forConnClosedEvent fn is modified");
		} else {
			if (!portRef.isConnIdValid(connId.get_int())) {
				IPL4_PORTREF_DEBUG(portRef, "IPL4asp__PT_PROVIDER.f__IPL4__PROVIDER__setGetMsgLen_forConnClosedEvent: invalid connId: %d", connId.get_int());
				return;
			}
			IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__setGetMsgLen_forConnClosedEvent: getMsgLen_forConnClosedEvent fn for connection %d is modified", connId.get_int());
			portRef.sockList.get(connId.get_int()).getMsgLen_forConnClosedEvent = f;
			portRef.sockList.get(connId.get_int()).msgLenArgs_forConnClosedEvent = null;
			portRef.sockList.get(connId.get_int()).msgLenArgs_forConnClosedEvent = new Socket__API__Definitions.ro__integer(msgLenArgs);
		}
	}

	protected Result f__IPL4__PROVIDER__listen(final IPL4asp__PT_PROVIDER portRef, final TitanCharString locName, final TitanInteger locPort, final ProtoTuple proto, final OptionList options) {
		SocketAddress sockAddr = null;
		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		int hp = 0;
		SSL_TLS_Type ssl_tls_type = SSL_TLS_Type.NONE;
		ProtoTuple my_proto = proto;

		if (TTCN_Logger.log_this_event(TTCN_Logger.Severity.PORTEVENT_MMSEND)) {
			TTCN_Logger.begin_event(TTCN_Logger.Severity.PORTEVENT_MMSEND);
			TTCN_Logger.log_event("entering f__IPL4__PROVIDER__listen: %s:%d / %s", locName.get_value().toString(), locPort.get_int(),
					proto.get_selection() == ProtoTuple.union_selection_type.ALT_udp ? "UDP"
							: proto.get_selection() == ProtoTuple.union_selection_type.ALT_udpLight ? "UDP Light"
									: proto.get_selection() == ProtoTuple.union_selection_type.ALT_tcp ? "TCP"
											: proto.get_selection() == ProtoTuple.union_selection_type.ALT_sctp ? "SCTP"
													: proto.get_selection() == ProtoTuple.union_selection_type.ALT_ssl
													? "SSL"
															: proto.get_selection() == ProtoTuple.union_selection_type.ALT_udpLight
															? "UDP Light"
																	: proto.get_selection() == ProtoTuple.union_selection_type.ALT_unspecified
																	? "Unspecified"
																			: proto.get_selection() == ProtoTuple.union_selection_type.ALT_dtls
																			? proto.get_field_dtls()
																					.get_selection() == Socket__API__Definitions.DtlsTuple.union_selection_type.ALT_udp
																					? "DTLS/UDP"
																							: proto.get_field_dtls()
																							.get_selection() == Socket__API__Definitions.DtlsTuple.union_selection_type.ALT_sctp
																							? "DTLS/SCTP"
																									: "DTLS/???"
																										: "???");
			TTCN_Logger.end_event();
		}
		IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: enter %s %d", locName.get_value().toString(), locPort.get_int());
		portRef.testIfInitialized();

		// check if all mandatory SSL config params are present for a listening socket
		if ((proto.get_selection() == ProtoTuple.union_selection_type.ALT_ssl) || (proto.get_selection() == ProtoTuple.union_selection_type.ALT_dtls)) {
			ssl_tls_type = SSL_TLS_Type.SERVER;	
		}
		// set tls_used if tls is used, and copy the proto coming in proto.dtls into my_proto
		if (proto.get_selection() == ProtoTuple.union_selection_type.ALT_dtls) {
			switch (proto.constGet_field_dtls().get_selection()) {
			case ALT_udp:
				my_proto.get_field_udp().operator_assign(proto.get_field_dtls().get_field_udp());
				break;
			case ALT_sctp:
				my_proto.get_field_sctp().operator_assign(proto.get_field_dtls().get_field_sctp());
				break;
			case UNBOUND_VALUE:
			default:
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__UNSUPPORTED__PROTOCOL), result, this);
			}
		}

		if (locPort.is_less_than(-1) || locPort.is_greater_than(65535)) {
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__INVALID__INPUT__PARAMETER), result, this);
		}

		sockAddr = SetLocalSockAddr("f__IPL4__PROVIDER__listen", portRef, AF_INET, locName.get_value().toString(), locPort.get_int());
		if (sockAddr == null) {
			// TODO: SET_OS_ERROR_CODE;
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__HOSTNAME), result, this);
		}

		// TODO: implement SCTP
		if (my_proto.get_selection() == ProtoTuple.union_selection_type.ALT_sctp) {
			int num_of_addr = 0;
			int addr_index = -1;
			String sarray[] = null;
			for (int i = 0; i < options.size_of().get_int(); i++) {
				if (options.get_at(i).get_selection() == Option.union_selection_type.ALT_sctpAdditionalLocalAddresses) {
					addr_index = i;
					num_of_addr = options.get_at(i).constGet_field_sctpAdditionalLocalAddresses().size_of().get_int();
					break;
				}
			}
			if (num_of_addr != 0) {
				sarray = new String[num_of_addr];
				IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: addr family main: %s ",hp== -1 ? "Error" : hp==AF_INET ? "AF_INET" : "AF_INET6");
				int final_hp = hp;
				for (int i = 0; i < num_of_addr; i++) {
					SocketAddress saLoc2 = SetLocalSockAddr("f__IPL4__PROVIDER__connect", portRef, hp, options.get_at(addr_index).constGet_field_sctpAdditionalLocalAddresses().get_at(i).get_value().toString(), locPort.get_int());
					IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: addr added Family: %s ",saLoc2 == null ? "Error" :  ((InetSocketAddress)(saLoc2)).getAddress() instanceof Inet4Address ? "AF_INET" : "AF_INET6");
					if (saLoc2 == null) {
						sarray = null;
						return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__HOSTNAME), result, this);
					}
					if (((InetSocketAddress)(saLoc2)).getAddress() instanceof Inet6Address) {
						final_hp = AF_INET6;
					}
				}
				hp = final_hp;
				IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: addr family final: %s ", hp == -1 ? "Error" : hp == AF_INET ? "AF_INET" : "AF_INET6"); 
			}

		}

		// create socket based on the transport protocol
		SockType sockType = null;
		SelectableChannel socket = null;
		switch (my_proto.get_selection()) {
		case ALT_udp:
			sockType = SockType.IPL4asp_UDP; // go further to the next case
		case ALT_udpLight:
			try {
				socket = DatagramChannel.open();
			} catch (IOException e) {
				System.err.println("Error on creating DatagramChannel : " + e.getMessage());
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
			}
			break;
		case ALT_ssl: // go further to the next case
		case ALT_tcp:
			sockType = SockType.IPL4asp_TCP_LISTEN;
			try {
				socket = ServerSocketChannel.open();
			} catch (IOException e) {
				System.err.println("Error on creating TCP ServerSocketChannel : " + e.getMessage());
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
			}
			break;
		case ALT_sctp:
			sockType = SockType.IPL4asp_SCTP_LISTEN;
			/*try {
				socket = SctpServerChannel.open();
			} catch (IOException e) {
				System.err.println("Error on creating SCTP ServerChannel : " + e.getMessage());
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
			} catch (UnsupportedOperationException e) {
				System.err.println("Error on creating SCTP ServerChannel : " + e.getMessage());
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__GENERAL), result, this);
			}*/
			break;
		default:
		case UNBOUND_VALUE:
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__UNSUPPORTED__PROTOCOL), result, this);
		}
		if (socket == null) {
			IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: failed to create new socket");
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
		}

		// set socket properties
		if (!portRef.setOptions(options, socket, my_proto, true)) {
			// TODO: finish
			IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: Setting options on socket %d failed.");
			try {
				socket.close();
			} catch (IOException e) {
				IPL4_DEBUG("f__IPL4__PROVIDER__listen: Channel.close() failed: %s", e.getMessage());
			}
		}

		if (socket instanceof ServerSocketChannel) {
			try {
				((ServerSocketChannel) socket).configureBlocking(false);
			} catch (IOException e) {
				IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: fcntl O_NONBLOCK on socket %s failed: %s", socket.toString(), e.getMessage());
				try {
					socket.close();
				} catch (IOException e1) {
					IPL4_DEBUG("f__IPL4__PROVIDER__listen: Channel.close() failed: %s", e1.getMessage());
				}
			}
		}

		if (socket instanceof DatagramChannel) {
			try {
				((DatagramChannel) socket).configureBlocking(false);
			} catch (IOException e) {
				IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: fcntl O_NONBLOCK on socket %s failed: %s", socket.toString(), e.getMessage());
				try {
					socket.close();
				} catch (IOException e1) {
					IPL4_DEBUG("f__IPL4__PROVIDER__listen: Channel.close() failed: %s", e1.getMessage());
				}
			}
		}
		/*if (socket instanceof SctpServerChannel) {
			try {
				((SctpServerChannel) socket).configureBlocking(false);
			} catch (IOException e) {
				IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: fcntl O_NONBLOCK on socket %s failed: %s", socket.toString(), e.getMessage());
				try {
					socket.close();
				} catch (IOException e1) {
					IPL4_DEBUG("f__IPL4__PROVIDER__listen: Channel.close() failed: %s", e1.getMessage());
				}
			}
		}*/
		//TODO: implement SSL

		int connId = -1;
		// bind
		switch (my_proto.get_selection()) {
		case ALT_udp:
			if (socket instanceof DatagramChannel) {
				try {
					((DatagramChannel) socket).bind(sockAddr);
				} catch (IOException e) {
					IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: bind on socket %s failed: %s", socket.toString(), e.getMessage());
					try {
						socket.close();
					} catch (IOException e1) {
						IPL4_DEBUG("f__IPL4__PROVIDER__listen: Channel.close() failed: %s", e1.getMessage());
					}
				}
			}
			connId = portRef.ConnAdd(sockType, socket, ssl_tls_type, options, -1);
			if (connId == -1) {
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__INSUFFICIENT__MEMORY), result, this);
			}
			result.get_field_connId().get().operator_assign(connId);
			break;
		case ALT_tcp:
			if (socket instanceof ServerSocketChannel) {
				try {
					((ServerSocketChannel) socket).bind(sockAddr, portRef.backlog);
				} catch (IOException e) {
					IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: bind on socket %s failed: %s", socket.toString(), e.getMessage());
					try {
						socket.close();
					} catch (IOException e1) {
						IPL4_DEBUG("f__IPL4__PROVIDER__listen: Channel.close() failed: %s", e1.getMessage());
					}
				}
			}
			connId = portRef.ConnAdd(sockType, socket, ssl_tls_type, options, -1);
			if (connId == -1) {
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__INSUFFICIENT__MEMORY), result, this);
			}
			result.get_field_connId().get().operator_assign(connId);
			break;
		case ALT_sctp:
			// TODO: implement sctp
			/*if (socket instanceof SctpServerChannel) {
				try {
					((SctpServerChannel) socket).bind(sockAddr, portRef.backlog);
					((SctpServerChannel) socket).register(TTCN_Snapshot.selector.get(), SelectionKey.OP_ACCEPT);
				} catch (IOException e) {
					IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: bind on socket %s failed: %s", socket.toString(), e.getMessage());
					try {
						socket.close();
					} catch (IOException e1) {
						IPL4_DEBUG("f__IPL4__PROVIDER__listen: Channel.close() failed: %s", e1.getMessage());
					}
				}
			}*/
			break;
		default:
		case UNBOUND_VALUE:
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__UNSUPPORTED__PROTOCOL), result, this);
		}
		portRef.set_dscp_option(socket);

		IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__listen: leave: socket created, connection ID: %d, socket: %s", connId, socket.toString());
		if (portRef.globalConnOpts.extendedPortEvents == GlobalConnOpts.YES) {
			IPL4asp__Types.ASP__Event event = new IPL4asp__Types.ASP__Event();
			event.get_field_result().operator_assign(result);
			portRef.incoming_message(event);
		}

		return result;
	}

	protected Result f__IPL4__PROVIDER__connect(final IPL4asp__PT_PROVIDER portRef, final TitanCharString remName, final TitanInteger remPort, final TitanCharString locName, final TitanInteger locPort, final TitanInteger connId, final ProtoTuple proto, final OptionList options) {
		// TODO: implement
		boolean einprog = false;
		SocketAddress saRem = null;
		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		int hp = 0;

		if (TTCN_Logger.log_this_event(Severity.PORTEVENT_MMSEND)) {
			TTCN_Logger.begin_event(Severity.PORTEVENT_MMSEND);
			TTCN_Logger.log_event("entering f__IPL4__PROVIDER__connect: %s:%d -> %s:%d / %s",
					locName.get_value().toString(), locPort.get_int(), remName.get_value().toString(),
					remPort.get_int(),
					proto.get_selection() == ProtoTuple.union_selection_type.ALT_udp ? "UDP"
							: proto.get_selection() == ProtoTuple.union_selection_type.ALT_udpLight ? "UDP Light"
									: proto.get_selection() == ProtoTuple.union_selection_type.ALT_tcp ? "TCP"
											: proto.get_selection() == ProtoTuple.union_selection_type.ALT_sctp ? "SCTP"
													: proto.get_selection() == ProtoTuple.union_selection_type.ALT_ssl
													? "SSL"
															: proto.get_selection() == ProtoTuple.union_selection_type.ALT_udpLight
															? "UDP Light"
																	: proto.get_selection() == ProtoTuple.union_selection_type.ALT_unspecified
																	? "Unspecified"
																			: proto.get_selection() == ProtoTuple.union_selection_type.ALT_dtls
																			? proto.constGet_field_dtls()
																					.get_selection() == Socket__API__Definitions.DtlsTuple.union_selection_type.ALT_udp
																					? "DTLS/UDP"
																							: proto.constGet_field_dtls()
																							.get_selection() == Socket__API__Definitions.DtlsTuple.union_selection_type.ALT_sctp
																							? "DTLS/SCTP"
																									: "DTLS/???"
																										: "???");
			TTCN_Logger.end_event();
		}

		IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: enter");
		portRef.testIfInitialized();

		if (remName.operator_equals("")) {
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__HOSTNAME), result, this);
		}
		if (remPort.is_less_than(0) || remPort.is_greater_than(65535) || locPort.is_less_than(-1) || locPort.is_greater_than(65535)) {
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__INVALID__INPUT__PARAMETER), result, this);
		}
		saRem = setSockAddr(remName.get_value().toString(), remPort.get_int());
		if (saRem == null) {
			// TODO: SET_OS_ERROR_CODE;
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__HOSTNAME), result, this);
		}
		SSL_TLS_Type ssl_tls_type = SSL_TLS_Type.NONE;
		ProtoTuple my_proto = proto;
		if (proto.get_selection() == ProtoTuple.union_selection_type.ALT_dtls) {
			ssl_tls_type = SSL_TLS_Type.CLIENT;
			IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: ssl_tls_type set to %d", ssl_tls_type);
			switch (proto.get_field_dtls().get_selection()) {
			case ALT_udp:
				my_proto.get_field_dtls().get_field_udp();
				break;
			case ALT_sctp:
				my_proto.get_field_dtls().get_field_sctp();
				break;
			default:
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__UNSUPPORTED__PROTOCOL), result, this);
			}
		}

		SelectableChannel sock = null;
		if (my_proto.get_selection() == ProtoTuple.union_selection_type.ALT_udp && connId.get_int() > 0) {
			if (!portRef.isConnIdValid(connId.get_int())) {
				IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: invalid connId: %d", connId.get_int());
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__INVALID__INPUT__PARAMETER), result, this);
			}
			result.get_field_connId().get().operator_assign(connId);
			sock = portRef.sockList.get(connId.get_int()).sock;
		} else {
			IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: create new socket: %s:%d -> %s:%d", locName.get_value().toString(), locPort.get_int(), remName.get_value().toString(), remPort.get_int());
			switch (my_proto.get_selection()) {
			case ALT_udp:
				// use the original proto here; in case DTLS is used
				result = f__IPL4__PROVIDER__listen(portRef, locName, locPort, proto, options);
				if (result.get_field_errorCode().is_present() && (result.get_field_errorCode().get().operator_not_equals(PortError.enum_type.ERROR__TEMPORARILY__UNAVAILABLE))) {
					return result;
				}
				IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: connId: %d", result.constGet_field_connId().constGet().get_int());
				sock = portRef.sockList.get(result.constGet_field_connId().constGet().get_int()).sock;

				break;
			case ALT_ssl:

				break;
			case ALT_tcp:
				SocketAddress saLoc = null;
				saLoc = SetLocalSockAddr("f__IPL4__PROVIDER__connect", portRef, hp, locName.get_value().toString(), locPort.get_int());
				if (saLoc == null) {
					// TODO: SET_OS_ERROR_CODE
					return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__HOSTNAME), result, this);
				}
				try {
					sock = SocketChannel.open();
				} catch (IOException e) {
					IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: failed to create new socket : ", e.getMessage());
					return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
				}

				// set socket properties
				if (!portRef.setOptions(options, sock, my_proto, true)) {
					// TODO: finish
					IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: Setting options on socket %d failed.");
					try {
						sock.close();
						return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
					} catch (IOException e) {
						IPL4_DEBUG("f__IPL4__PROVIDER__connect: SocketChannel.close() failed: %s", e.getMessage());
						return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
					}
				}

				if (sock instanceof SocketChannel) {
					try {
						((SocketChannel) sock).configureBlocking(false);
					} catch (IOException e) {
						IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: Non-blocking mode on socket %s failed: %s", sock.toString(), e.getMessage());
						try {
							sock.close();
						} catch (IOException e1) {
							IPL4_DEBUG("f__IPL4__PROVIDER__connect: SocketChannel.close() failed: %s", e1.getMessage());
						}
					}
				}

				if (sock instanceof SocketChannel) {
					try {
						((SocketChannel) sock).bind(saLoc);
					} catch (IOException e) {
						IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: bind on socket %s failed: %s", sock.toString(), e.getMessage());
						try {
							sock.close();
							return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
						} catch (IOException e1) {
							IPL4_DEBUG("f__IPL4__PROVIDER__connect: SocketChannel.close() failed: %s", e1.getMessage());
							return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
						}
					}
				}
				portRef.set_dscp_option(sock);
				break;
			case ALT_sctp:
				// TODO: implement sctp
				break;
			case UNBOUND_VALUE:
			default:
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__UNSUPPORTED__PROTOCOL), result, this);
			}

		}

		switch (my_proto.get_selection()) {
		case ALT_udp:
			IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: sock: %s", sock.toString());
			if (sock instanceof DatagramChannel) {
				try {
					((DatagramChannel) sock).connect(saRem);
					if (((DatagramChannel) sock).isConnected()) {
						einprog = true;
					}
				} catch (IOException e) {
					IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: error: %s", e.getMessage());
					return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
				}
			}
			IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: udp socket connected, connection ID: %d", result.constGet_field_connId().constGet().get_int());
			break;
		case ALT_tcp:
			IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: sock: %s", sock.toString());
			if (sock instanceof SocketChannel) {
				try {
					boolean finish = false;
					((SocketChannel) sock).connect(saRem);
					if (((SocketChannel) sock).isConnectionPending()) {
						finish = ((SocketChannel) sock).finishConnect();
						einprog = true;
					}
					if (!finish) {
						einprog = false;
						return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
					}
				} catch (IOException e) {
					IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: error: %s", e.getMessage());
					if (!einprog) {
						if ((my_proto.get_selection() == ProtoTuple.union_selection_type.ALT_tcp) || (my_proto.get_selection() == ProtoTuple.union_selection_type.ALT_ssl)) {
							if (sock instanceof SocketChannel) {
								try {
									((SocketChannel) sock).close();
									IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: socket %s is closed.", sock.toString());
									return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
								} catch (IOException e1) {
									IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: error: %s", e1.getMessage());
									return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
								}
							}
						} else {
							// The UDP socket has already been added to sockList and even if it
							// cannot be connected to some remote destination, it can still be used
							// as a listening socket or with the SendTo ASP. Therefore, it is not
							// removed from connList in case of error. But it is going to be removed,
							// if the socket has been created in this operation.
							if (connId.operator_equals(-1)) {
								if (portRef.ConnDel(result.constGet_field_connId().get().get_int(), true) == -1) {
									IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: unable to close socket %s", sock.toString());
									result.get_field_connId().operator_assign(template_sel.OMIT_VALUE);
								}
							}
							return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
						}
					}
				}
				if (my_proto.get_selection() == ProtoTuple.union_selection_type.ALT_tcp) {
					int l_connId = portRef.ConnAdd(SockType.IPL4asp_TCP, sock, ssl_tls_type, options, -1);
					if (l_connId == -1) {
						return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__INSUFFICIENT__MEMORY), result, this);
					}
					result.get_field_connId().get().operator_assign(l_connId);
					if (portRef.sockList.containsKey(l_connId)) {
						if (portRef.sockList.get(l_connId).remoteport.operator_equals(-1)) {
							portRef.sockList.get(l_connId).remoteaddr.operator_assign(remName);
							portRef.sockList.get(l_connId).remoteport.operator_assign(remPort);
						}
					}
				} else {
					IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: udp socket connected, connection ID: %d", result.constGet_field_connId().constGet().get_int());
					break;
				}
			}

			if (einprog) {
				if (portRef.pureNonBlocking) {
					// TODO: finish handler
					try {
						portRef.Install_Handler(null, Set.of(sock), 0.0);
						IPL4_PORTREF_DEBUG(portRef, "DO WRITE ON %s", sock.toString());
					} catch (IOException e) {
						IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: leave (TEMPORARILY UNAVAILABLE)   fd: %s", sock);
						return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
					}
					result.get_field_errorCode().operator_assign(template_sel.OMIT_VALUE);
				}
			}
			break;
		case ALT_ssl:
			break;
		default:
		case UNBOUND_VALUE:
			break;
		}
		IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__connect: leave");
		if (portRef.globalConnOpts.extendedPortEvents == GlobalConnOpts.YES) {
			IPL4asp__Types.ASP__Event event = new IPL4asp__Types.ASP__Event();
			event.get_field_result().operator_assign(result);
			portRef.incoming_message(event);
		}
		return result;
	}

	protected Result f__IPL4__PROVIDER__setOpt(IPL4asp__PT_PROVIDER portRef, final OptionList options, final TitanInteger connId, final ProtoTuple proto) {
		portRef.testIfInitialized();
		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		ProtoTuple protocol = proto;
		SelectableChannel sock = null;
		if (connId.get_int() != -1) {
			if (!portRef.isConnIdValid(connId.get_int())) {
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__INVALID__INPUT__PARAMETER), result, this);
			}
			sock = portRef.sockList.get(connId.get_int()).sock;
			SockType type = null;
			if (!portRef.getAndCheckSockType(connId.get_int(), proto.get_selection(), type)) {
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
			}
			switch (type) {
			case IPL4asp_TCP_LISTEN:
			case IPL4asp_TCP:
				if (portRef.sockList.get(connId.get_int()).ssl_tls_type == SSL_TLS_Type.NONE) {
					protocol.get_field_tcp().operator_assign(new TcpTuple(TitanNull_Type.NULL_VALUE));
				} else {
					protocol.get_field_ssl().operator_assign(new SslTuple(TitanNull_Type.NULL_VALUE));
				}
				break;
			case IPL4asp_UDP:
				protocol.get_field_udp().operator_assign(new UdpTuple(TitanNull_Type.NULL_VALUE));
				break;
			case IPL4asp_SCTP_LISTEN:
			case IPL4asp_SCTP:
				protocol.get_field_sctp().operator_assign(new SctpTuple(new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(Socket__API__Definitions.SocketList.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE)));
				break;
			default:
				break;
			}
		}
		if (!portRef.setOptions(options, sock, protocol, false)) {
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
		}
		if (connId.get_int() != -1) {
			//TODO: implement set_ssl_supp_option
		}
		return result;
	}

	//TODO: finish
	protected Extended__Result f__IPL4__PROVIDER__getOpt(IPL4asp__PT_PROVIDER portRef, final Option option, final TitanInteger connId, final ProtoTuple proto) {
		Extended__Result result = new Extended__Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE), new Optional<>(TitanOctetString.class, template_sel.OMIT_VALUE));

		portRef.testIfInitialized();
		ProtoTuple protocol = proto;

		SelectableChannel sock = null;
		if (connId.get_int() != -1) {
			if (!portRef.isConnIdValid(connId.get_int())) {
				//TODO: RETURN_EXTENDED_ERROR(ERROR__INVALID__INPUT__PARAMETER);
				return null;
			}

			sock = portRef.sockList.get(connId.get_int()).sock;
			SockType type = null;
			if (!portRef.getAndCheckSockType(connId.get_int(), proto.get_selection(), type)) {
				//TODO: RETURN_EXTENDED_ERROR(ERROR__SOCKET);
				return null;
			}
		}
		int socketValue = portRef.getOption(option, sock, protocol, false);
		if (socketValue < 0) {
			//TODO: RETURN_EXTENDED_ERROR(ERROR__SOCKET);
			return null;
		} else {
			result.get_field_msg().get().operator_assign(AdditionalFunctions.int2oct(socketValue, 4));
		}
		return result;
	}

	protected Result f__IPL4__PROVIDER__close(IPL4asp__PT_PROVIDER portRef, final TitanInteger connId, final ProtoTuple proto) {
		IPL4_PORTREF_DEBUG(portRef, "f__IPL4__PROVIDER__close: enter: connId: %d", connId.get_int());
		portRef.testIfInitialized();
		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		SockType type = null;
		if (!portRef.getAndCheckSockType(connId.get_int(), proto.get_selection(), type)) {
			if (portRef.isConnIdReleaseWait(connId.get_int())) {
				return result;
			}
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__INVALID__INPUT__PARAMETER), result, this);
		}
		if (type == SockType.IPL4asp_SCTP || type == SockType.IPL4asp_SCTP_LISTEN) {
			//TODO: implement SCTP
		} else {
			if (portRef.ConnDel(connId.get_int(), true) == -1) {
				return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__SOCKET), result, this);
			}
		}
		result.get_field_connId().get().operator_assign(connId);
		if (portRef.globalConnOpts.extendedPortEvents == GlobalConnOpts.YES) {
			ASP__Event event = new ASP__Event();
			event.get_field_result().operator_assign(result);
			portRef.incoming_message(event);
		}
		return result;
	}

	protected Result f__IPL4__PROVIDER__setUserData(IPL4asp__PT_PROVIDER portRef, final TitanInteger id, final TitanInteger userData) {
		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		if (portRef.setUserData(id.get_int(), userData.get_int()) == -1) {
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__GENERAL), result, this);
		}
		return result;
	}

	protected Result f__IPL4__PROVIDER__getUserData(IPL4asp__PT_PROVIDER portRef, final TitanInteger id, TitanInteger userData) {
		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		int userDataTemp = 0;
		if (portRef.getUserData(id.get_int(), userDataTemp) == -1) {
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__GENERAL), result, this);
		}
		userData.operator_assign(userDataTemp);
		return result;
	}

	protected Result f__IPL4__PROVIDER__getConnectionDetails(IPL4asp__PT_PROVIDER portRef, final TitanInteger connId, final IPL4__Param IPL4param, IPL4__ParamResult IPL4paramResult) {
		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		IPL4__ParamResult paramResult = new IPL4__ParamResult();
		if (portRef.getConnectionDetails(connId.get_int(), IPL4param, paramResult) == -1) {
			return RETURN_ERROR(PortError.enum2int(PortError.enum_type.ERROR__GENERAL), result, this);
		}
		IPL4paramResult = paramResult;
		return result;
	}

	protected Result f__IPL4__PROVIDER__port__settings(IPL4asp__PT_PROVIDER portRef, final TitanCharString param__name, final TitanCharString param__value) {
		portRef.set_parameter(param__name.get_value().toString(), param__value.get_value().toString());
		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));

		return result;
	}

	protected Result f__IPL4__PROVIDER__ConnId__release(IPL4asp__PT_PROVIDER portRef, final TitanInteger connId) {
		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		if (TTCN_Logger.log_this_event(TTCN_Logger.Severity.PORTEVENT_MMSEND)) {
			TTCN_Logger.begin_event(TTCN_Logger.Severity.PORTEVENT_MMSEND);
			TTCN_Logger.log_event("%s: f__IPL4__ConnId__release: ", portRef.get_name());
			TTCN_Logger.log_event(" connId ");
			connId.log();
			TTCN_Logger.end_event();
		}

		if (portRef.isConnIdReleaseWait(connId.get_int())) {
			//Use ConnDel instead of ConnFree
			portRef.ConnDel(connId.get_int(), true);
		} else {
			result.get_field_errorCode().get().operator_assign(PortError.enum_type.ERROR__INVALID__INPUT__PARAMETER);
			result.get_field_os__error__code().get().operator_assign(-1);
			result.get_field_os__error__text().get().operator_assign("The f_IPL4_ConnId_release called in wrong state");
		}

		if (TTCN_Logger.log_this_event(TTCN_Logger.Severity.PORTEVENT_MMRECV)) {
			TTCN_Logger.begin_event(TTCN_Logger.Severity.PORTEVENT_MMRECV);
			TTCN_Logger.log_event("%s: f_IPL4_ConnId_release result: ", portRef.get_name());
			result.log();
			TTCN_Logger.end_event();
		}

		return result;
	}

	public static class thread_log {
		TTCN_Logger.Severity severity;
		String msg;
	}

	public static class SSL_Support {
		public int SSLv2; /* YES, NO, NOT_SET */
		public int SSLv3; /* YES, NO, NOT_SET */
		public int TLSv1; /* YES, NO, NOT_SET */
		public int TLSv1_1; /* YES, NO, NOT_SET */
		public int TLSv1_2; /* YES, NO, NOT_SET */
		public int DTLSv1; /* YES, NO, NOT_SET */
		public int DTLSv1_2; /* YES, NO, NOT_SET */

		public SSL_Support() {
			this.SSLv2 = -1;
			this.SSLv3 = -1;
			this.TLSv1 = -1;
			this.TLSv1_1 = -1;
			this.TLSv1_2 = -1;
			this.DTLSv1 = -1;
			this.DTLSv1_2 = -1;
		}

		public SSL_Support(int sSLv2, int sSLv3, int tLSv1, int tLSv1_1, int tLSv1_2, int dTLSv1, int dTLSv1_2) {
			this.SSLv2 = sSLv2;
			this.SSLv3 = sSLv3;
			this.TLSv1 = tLSv1;
			this.TLSv1_1 = tLSv1_1;
			this.DTLSv1 = tLSv1_2;
			this.DTLSv1 = dTLSv1;
			this.DTLSv1_2 = dTLSv1_2;
		}
	}

	public static class SockDesc {

		public enum SocketStatus {
			SOCK_NONEX(-1), SOCK_CLOSED(-2), SOCK_NOT_KNOWN(-3), WAIT_FOR_RELEASE(-4);

			private int value;

			SocketStatus(final int value) {
				this.value = value;
			}
		};

		public enum SocketAction {
			ACTION_NONE(0), ACTION_BIND(1), ACTION_CONNECT(2), ACTION_DELETE(3);

			private int value;

			SocketAction(final int value) {
				this.value = value;
			}
		};

		public SockType type;
		public SSL_TLS_Type ssl_tls_type;
		public SelectableChannel sock;
		public TTCN_Buffer buf;
		public int assocIdList;
		public int cnt;
		public int userData;

		public Socket__API__Definitions.f__getMsgLen getMsgLen;
		public Socket__API__Definitions.f__getMsgLen getMsgLen_forConnClosedEvent;
		public Socket__API__Definitions.ro__integer msgLenArgs;
		public Socket__API__Definitions.ro__integer msgLenArgs_forConnClosedEvent;

		public int msgLen; // -1 or the message length returned by getMsgLen
		public int nextFree; // -1 or index of next free element
		public int parentIdx; // parent index (-1 if no)

		public SSLContext sslCTX;
		public String dtlsSrtpProfiles; // DTLS SRTP profiles, see RCF 5764
		public String ssl_key_file; // private key file
		public String ssl_certificate_file; // own certificate file
		public String ssl_trustedCAlist_file; // trusted CA list file
		public String ssl_cipher_list; // ssl_cipher list restriction to apply
		public String ssl_password; // password to decode the private key
		public String psk_identity;
		public String psk_identity_hint;
		public String psk_key;
		public boolean server;
		public boolean sctpHandshakeCompletedBeforeDtls;
		public InetAddress sa_client; // TODO: maybe SocketAddress
		public SSL_Support ssl_supp = new SSL_Support();
		public SSL_STATES sslState;

		public TitanInteger localport;
		public TitanCharString localaddr;
		public TitanInteger remoteport;
		public TitanCharString remoteaddr;

		public TitanCharString tls_hostname;
		public TitanOctetString alpn;

		public int next_action;
		public int endpoint_id;
		public int ref_count;
		public int remote_addr_index;
		public int maxOs;
		public Socket__API__Definitions.SocketList remote_addr_list;

		public void clear() {
			for (int i = 0; i < cnt; ++i) {
				buf.clear();
			}
			cnt = 0;
			assocIdList = 0;
			msgLenArgs.clean_up();
			msgLenArgs_forConnClosedEvent.clean_up();
			localaddr.clean_up();
			localport.clean_up();
			if (remoteaddr != null) {
				remoteaddr.clean_up();
			}
			if (remoteport != null) {
				remoteport.clean_up();
			}

			tls_hostname = null;

			alpn = null;

			ssl_key_file = null;
			ssl_certificate_file = null;
			ssl_trustedCAlist_file = null;
			ssl_cipher_list = null;
			ssl_password = null;
			psk_identity = null;
			psk_identity_hint = null;
			psk_key = null;
			if (dtlsSrtpProfiles != null) {
				dtlsSrtpProfiles = null;
			}
			sock = null;
			msgLen = -1;
			nextFree = -1;
		}
	}

	public static class IPDiscConfig {

		public enum Type {
			NONE, DHCP, DHCP_OR_ARP, ARP
		}

		public Type type;
		public TitanCharString expIfName;
		public TitanCharString exclIfIpAddress;
		public TitanCharString expIfIpAddress;
		public TitanCharString ethernetAddress;
		public int leaseTime;
		public TitanCharString leaseFile;
		public int nOfAddresses;
		public boolean debugAllowed;
		public int dhcpMsgRetransmitCount;
		public int dhcpMsgRetransmitPeriodInms;
		public int dhcpMaxParallelRequestCount;
		public long dhcpTimeout;
		public int arpMsgRetransmitCount;
		public int arpMsgRetransmitPeriodInms;
		public int arpMaxParallelRequestCount;

		public IPDiscConfig() {
			this.type = Type.NONE;
			this.leaseTime = 0;
			this.debugAllowed = false;
			this.dhcpMsgRetransmitCount = 5;
			this.dhcpMsgRetransmitPeriodInms = 3000;
			this.dhcpMaxParallelRequestCount = 25;
			this.dhcpTimeout = 1000000000;
			this.arpMsgRetransmitCount = 3;
			this.arpMsgRetransmitPeriodInms = 1000;
			this.arpMaxParallelRequestCount = 50;
		}
	}

	public static class IPAddrLease {

		public TitanCharString ifName;
		public TitanCharString leaseFile;
	}

	public static class GlobalConnOpts {

		private static final int NOT_SET = -1;
		private static final int NO = 0;
		private static final int YES = 1;
		private static final int METHOD_ZERO = 0;
		private static final int METHOD_ONE = 1;
		private static final int METHOD_TWO = 2;

		int connection_method; /* METHOD_ZERO, METHOD_ONE, METHOD_TWO */
		int tcpReuseAddr; /* YES, NO, NOT_SET */
		int udpReuseAddr; /* YES, NO, NOT_SET */
		int sctpReuseAddr; /* YES, NO, NOT_SET */
		int sslReuseAddr; /* YES, NO, NOT_SET */
		int tcpKeepAlive; /* YES, NO, NOT_SET */
		int tcpKeepCnt; /* NOT_SET, 0.. */
		int tcpKeepIdle; /* NOT_SET, 0.. */
		int tcpKeepIntvl; /* NOT_SET, 0.. */
		int sslKeepAlive; /* YES, NO, NOT_SET */
		int sslKeepCnt; /* NOT_SET, 0.. */
		int sslKeepIdle; /* NOT_SET, 0.. */
		int sslKeepIntvl; /* NOT_SET, 0.. */
		int extendedPortEvents; /* YES, NO, NOT_SET */
		int sinit_num_ostreams; /* 64, 0.. */ // sctp specific params starts here
		int sinit_max_instreams; /* 64, 0.. */
		int sinit_max_attempts; /* 0, 0.. */
		int sinit_max_init_timeo; /* 0, 0.. */
		int sctp_data_io_event; /* YES, NO, NOT_SET */
		int sctp_association_event; /* YES, NO, NOT_SET */
		int sctp_address_event; /* YES, NO, NOT_SET */
		int sctp_send_failure_event; /* YES, NO, NOT_SET */
		int sctp_peer_error_event; /* YES, NO, NOT_SET */
		int sctp_shutdown_event; /* YES, NO, NOT_SET */
		int sctp_partial_delivery_event; /* YES, NO, NOT_SET */
		int sctp_adaptation_layer_event; /* YES, NO, NOT_SET */
		int sctp_authentication_event; /* YES, NO, NOT_SET */
		int sctp_sender_dry_event;
		int tcp_nodelay; /* YES, NO, NOT_SET */
		int sctp_nodelay; /* YES, NO, NOT_SET */
		int freebind;
		SSL_Support ssl_supp;
		String dtlsSrtpProfiles; /* SRTP_AES128_CM_SHA1_32:SRTP_AES128_CM_SHA1_80 */
		int dscp; /* NOT_SET, 0.. */

		public GlobalConnOpts() {
			this.connection_method = METHOD_ZERO;
			this.tcpReuseAddr = YES;
			this.udpReuseAddr = YES;
			this.sctpReuseAddr = YES;
			this.sslReuseAddr = YES;
			this.tcpKeepAlive = NOT_SET;
			this.tcpKeepCnt = NOT_SET;
			this.tcpKeepIdle = NOT_SET;
			this.tcpKeepIntvl = NOT_SET;
			this.sslKeepAlive = NOT_SET;
			this.sslKeepCnt = NOT_SET;
			this.sslKeepIdle = NOT_SET;
			this.sslKeepIntvl = NOT_SET;
			this.extendedPortEvents = NO;
			this.sinit_num_ostreams = 64;
			this.sinit_max_instreams = 64;
			this.sinit_max_attempts = 0;
			this.sinit_max_init_timeo = 0;
			this.sctp_data_io_event = YES;
			this.sctp_association_event = YES;
			this.sctp_address_event = YES;
			this.sctp_send_failure_event = YES;
			this.sctp_peer_error_event = YES;
			this.sctp_shutdown_event = YES;
			this.sctp_partial_delivery_event = YES;
			this.sctp_adaptation_layer_event = YES;
			this.sctp_authentication_event = NO;
			this.sctp_sender_dry_event = NO;
			this.tcp_nodelay = NOT_SET;
			// this.ssl_nodelay = NOT_SET;
			this.sctp_nodelay = NOT_SET;
			this.freebind = NOT_SET;
			this.ssl_supp = new SSL_Support(YES, YES, YES, YES, YES, YES, YES);
			this.dtlsSrtpProfiles = null;
			this.dscp = NOT_SET;
		}
	}
}