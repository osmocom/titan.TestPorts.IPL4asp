package org.eclipse.titan.titan_JavaTestPorts_IPL4.user_provided;

import java.math.BigInteger;

import org.eclipse.titan.runtime.core.Optional;
import org.eclipse.titan.runtime.core.TTCN_Logger;
import org.eclipse.titan.runtime.core.TitanCharString;
import org.eclipse.titan.runtime.core.TitanInteger;
import org.eclipse.titan.runtime.core.TitanOctetString;
import org.eclipse.titan.runtime.core.Base_Template.template_sel;
import org.eclipse.titan.runtime.core.TTCN_Logger.Severity;

import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.OptionList;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__PortType.IPL4asp__PT;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.IPL4__Param;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.IPL4__ParamResult;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.Option;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.f__IPL4__getMsgLen;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.ASP__Send;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.IPL4asp__Types.ASP__SendTo;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.Extended__Result;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.PortError;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.ProtoTuple;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.Result;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.generated.Socket__API__Definitions.ro__integer;
import org.eclipse.titan.titan_JavaTestPorts_IPL4.user_provided.IPL4asp__PT_PROVIDER.SSL_TLS_Type;

public class IPL4asp__PortType_externalfunctions {

	public static Result f__IPL4__connect(IPL4asp__PT portRef, final TitanCharString remName, final TitanInteger remPort, final TitanCharString locName, final TitanInteger locPort, final TitanInteger connId, final ProtoTuple proto, final OptionList options) {
		Result result = portRef.f__IPL4__PROVIDER__connect(portRef, remName, remPort, locName, locPort, connId, proto, options);
		if (TTCN_Logger.log_this_event(Severity.PORTEVENT_MMRECV)) {
			TTCN_Logger.begin_event(Severity.PORTEVENT_MMRECV);
			TTCN_Logger.log_event("%s: f_IPL4_connect result: ", portRef.get_name());
			result.log();
			TTCN_Logger.end_event();
		}
		return result;
	}

	public static Result f__IPL4__listen(IPL4asp__PT portRef, final TitanCharString locName, final TitanInteger locPort, final ProtoTuple proto, final OptionList options) {
		Result result = portRef.f__IPL4__PROVIDER__listen(portRef, locName, locPort, proto, options);
		if (TTCN_Logger.log_this_event(Severity.PORTEVENT_MMRECV)) {
			TTCN_Logger.begin_event(Severity.PORTEVENT_MMRECV);
			TTCN_Logger.log_event("%s: f_IPL4_listen result: ", portRef.get_name());
			result.log();
			TTCN_Logger.end_event();
		}
		return result;
	}

	public static Result f__IPL4__close(IPL4asp__PT portRef, final TitanInteger connId, final ProtoTuple proto) {
		if (TTCN_Logger.log_this_event(Severity.PORTEVENT_MMSEND)) {
			TTCN_Logger.begin_event(Severity.PORTEVENT_MMSEND);
			TTCN_Logger.log_event("%s: f__IPL4__close: ", portRef.get_name());
			TTCN_Logger.log_event(" proto ");
			proto.log();
			TTCN_Logger.log_event(" connId ");
			connId.log();
			TTCN_Logger.end_event();
		}
		Result result = portRef.f__IPL4__PROVIDER__close(portRef, connId, proto);
		if (TTCN_Logger.log_this_event(Severity.PORTEVENT_MMRECV)) {
			TTCN_Logger.begin_event(Severity.PORTEVENT_MMRECV);
			TTCN_Logger.log_event("%s: f__IPL4__close result: ", portRef.get_name());
			result.log();
			TTCN_Logger.end_event();
		}
		return result;
	}

	public static Result f__IPL4__setUserData(IPL4asp__PT portRef, final TitanInteger connId, final TitanInteger userData) {
		return portRef.f__IPL4__PROVIDER__setUserData(portRef, connId, userData);
	}

	public static Result f__IPL4__getUserData(IPL4asp__PT portRef, final TitanInteger connId, TitanInteger userData) {
		return portRef.f__IPL4__PROVIDER__getUserData(portRef, connId, userData);
	}

	public static Result f__IPL4__setOpt(IPL4asp__PT portRef, final OptionList options, final TitanInteger connId, final ProtoTuple proto) {
		return portRef.f__IPL4__PROVIDER__setOpt(portRef, options, connId, proto);
	}

	public static Extended__Result f__IPL4__getOpt(IPL4asp__PT portRef, final Option option, final TitanInteger connId, final ProtoTuple proto) {
		return portRef.f__IPL4__PROVIDER__getOpt(portRef, option, connId, proto);
	}

	public static void f__IPL4__setGetMsgLen(IPL4asp__PT portRef, final TitanInteger connId, f__IPL4__getMsgLen f, ro__integer msgLenArgs) {
		portRef.f__IPL4__PROVIDER__setGetMsgLen(portRef, connId, f, msgLenArgs);
	}

	public static void f__IPL4__setGetMsgLen__forConnClosedEvent(IPL4asp__PT portRef, final TitanInteger connId, f__IPL4__getMsgLen f, ro__integer msgLenArgs) {
		portRef.f__IPL4__PROVIDER__setGetMsgLen__forConnClosedEvent(portRef, connId, f, msgLenArgs);
	}

	public static Result f__IPL4__getConnectionDetails(IPL4asp__PT portRef, final TitanInteger connId, final IPL4__Param IPL4param, IPL4__ParamResult IPL4paramResult) {
		return portRef.f__IPL4__PROVIDER__getConnectionDetails(portRef, connId, IPL4param, IPL4paramResult);
	}

	public static Result f__IPL4__port__settings(IPL4asp__PT portRef, final TitanCharString param__name, final TitanCharString param__value) {
		return portRef.f__IPL4__PROVIDER__port__settings(portRef, param__name, param__value);
	}

	public static Result f__IPL4__send(IPL4asp__PT portRef, final ASP__Send asp, TitanInteger sent__octets) {
		if (TTCN_Logger.log_this_event(TTCN_Logger.Severity.PORTEVENT_MMSEND)) {
			TTCN_Logger.begin_event(TTCN_Logger.Severity.PORTEVENT_MMSEND);
			TTCN_Logger.log_event("%s: f_IPL4_send: ", portRef.get_name());
			asp.log();
			TTCN_Logger.end_event();
		}

		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		sent__octets.operator_assign(portRef.outgoing_send_core(asp,result)); 

		if (TTCN_Logger.log_this_event(TTCN_Logger.Severity.PORTEVENT_MMRECV)) {
			TTCN_Logger.begin_event(TTCN_Logger.Severity.PORTEVENT_MMRECV);
			TTCN_Logger.log_event("%s: f_IPL4_send result: ", portRef.get_name());
			result.log();
			TTCN_Logger.end_event();
		}

		return result;
	}

	public static Result f__IPL4__sendto(IPL4asp__PT portRef, final ASP__SendTo asp, TitanInteger sent__octets) {
		if (TTCN_Logger.log_this_event(TTCN_Logger.Severity.PORTEVENT_MMSEND)) {
			TTCN_Logger.begin_event(TTCN_Logger.Severity.PORTEVENT_MMSEND);
			TTCN_Logger.log_event("%s: f_IPL4_sendto: ", portRef.get_name());
			asp.log();
			TTCN_Logger.end_event();
		}

		Result result = new Result(new Optional<>(PortError.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanInteger.class, template_sel.OMIT_VALUE), new Optional<>(TitanCharString.class, template_sel.OMIT_VALUE));
		sent__octets.operator_assign(portRef.outgoing_send_core(asp,result)); 

		if (TTCN_Logger.log_this_event(TTCN_Logger.Severity.PORTEVENT_MMRECV)) {
			TTCN_Logger.begin_event(TTCN_Logger.Severity.PORTEVENT_MMRECV);
			TTCN_Logger.log_event("%s: f_IPL4_sendto result: ", portRef.get_name());
			result.log();
			TTCN_Logger.end_event();
		}

		return result;

	}

	public static Result f__IPL4__ConnId__release(IPL4asp__PT portRef, final TitanInteger connId) {
		return portRef.f__IPL4__PROVIDER__ConnId__release(portRef, connId);
	}

	public static TitanInteger f__IPL4__fixedMsgLen(final TitanOctetString stream, ro__integer msgLenArgs) {
		int length_offset = msgLenArgs.get_at(0).get_int();
		int nr_bytes_in_length = msgLenArgs.get_at(1).get_int();

		int stream_length = stream.lengthof().get_int();

		if (stream_length < (length_offset + nr_bytes_in_length)) {
			return new TitanInteger(-1);  // not enough bytes
		}

		int length_multiplier = msgLenArgs.get_at(3).get_int();
		int value_offset = msgLenArgs.get_at(2).get_int();

		int shift_diff = 0;
		int shift_count = 0;

		if (msgLenArgs.get_at(4).get_int() == 1) {
			shift_count = 0;  // Little endian
			shift_diff = 1;
		} else {
			shift_count = nr_bytes_in_length - 1;  // Big endian
			shift_diff = -1;
		}

		long m_length = 0;

		byte buff[] = stream.get_value();

		//Original: stream + length_offset
		for (int i = length_offset; i < nr_bytes_in_length; i++) {
			m_length |= buff[i] << (8 * shift_count);
			shift_count += shift_diff;
		}
		m_length *= length_multiplier;
		if (value_offset < 0 && m_length < -value_offset) {
			return new TitanInteger(stream_length);
		} else if ((m_length + value_offset) > Integer.MAX_VALUE) {
			return new TitanInteger(BigInteger.valueOf((m_length + value_offset)));
		} else {
			return new TitanInteger((int)(m_length + value_offset));
		}
	}
}
