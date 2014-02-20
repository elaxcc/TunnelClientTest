#include "stdafx.h"

#include "TunnelClient.h"

TunnelClient::TunnelClient(short int initial_polling_flags_,
	bool nonblocking, bool no_nagle_delay)
	: Net::client(initial_polling_flags_, nonblocking, no_nagle_delay)
	, protocol_(this)
{
	protocol_.switch_to_send(ProtocolParser::Out_packet_type_send_internal_rsa_pub_key);
}

TunnelClient::~TunnelClient()
{
	protocol_.reset();
}

int TunnelClient::process_events(short int polling_events)
{
	if (polling_events == Net::c_poll_event_in)
	{
		c_Debug() << "TunnelClient::process_events, get packet\r\n";

		// receive data from socket
		std::vector<char> recv_data;
		int recv_result = Net::recv_all(get_socket(), recv_data);
		if (recv_result == Net::error_connection_is_closed_)
		{
			return Net::error_connection_is_closed_;
		}

		// parse packet
		if (!recv_data.empty())
		{
			int parse_result = protocol_.parse(recv_data);
			//!fixme process parse_result
		}
		if (protocol_.is_complete())
		{
			int result = protocol_.process_in();
			if (result == TunnelCommon::Protocol::Error_rsa_key_packet)
			{
				return Net::error_connection_is_closed_;
			}
		}
	}
	else if (polling_events == Net::c_poll_event_out)
	{
		protocol_.process_out();
	}

	return Net::error_no_;
}
