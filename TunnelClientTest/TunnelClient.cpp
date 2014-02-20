#include "stdafx.h"

#include "TunnelClient.h"

TunnelClient::TunnelClient(short int initial_polling_flags_,
	bool nonblocking, bool no_nagle_delay)
	: Net::client(initial_polling_flags_, nonblocking, no_nagle_delay)
	, protocol_(this)
{
}

TunnelClient::~TunnelClient()
{
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
		if (protocol_.got_rsa_key())
		{
			int parse_result = protocol_.parse_common(recv_data);
			//!fixme process parse_result
		}
		if (protocol_.is_complete())
		{
			protocol_.process_in();
		}
	}
	else if (polling_events == Net::c_poll_event_out)
	{
		protocol_.process_out();
	}

	return Net::error_no_;
}
