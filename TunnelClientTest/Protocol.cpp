#include "stdafx.h"

#include "Protocol.h"

#include "TunnelClient.h"

namespace
{

const std::string packet_user_accept = "Hello user!!!";

} // namespace

ProtocolParser::ProtocolParser(TunnelClient *own_node)
	: own_node_(own_node)
	, out_packet_type_(Out_packet_type_no_packet)
{
}

ProtocolParser::~ProtocolParser()
{
	reset();
}

int ProtocolParser::process_in()
{
	switch (get_packet_type())
	{
	case Packet_type_external_rsa_key :
		{
			c_Debug() << "process packet, type == 'Packet_type_external_rsa_key'" << "\r\n";

			if (!got_rsa_key())
			{
				// process external RSA public key
				if (parse_external_rsa_key_packet() == ProtocolParser::Error_no)
				{
					// send internal RSA public key
					std::vector<char> packet;
					int parse_result = prepare_rsa_internal_pub_key_packet(packet);
					if (parse_result == ProtocolParser::Error_no)
					{
						c_Debug() << "process packet, type == 'Packet_type_external_rsa_key', OK" << "\r\n";
						return Error_no;
					}
				}
				c_Debug() << "process packet, type == 'Packet_type_external_rsa_key', Error_rsa_key_packet" << "\r\n";
				return Error_rsa_key_packet;
			}
			break;
		}
	default:
		{
			c_Debug() << "process packet, Error_unknown_packet" << "\r\n";
			return Error_unknown_packet;
		}
	}
	return Error_no;
}

int ProtocolParser::process_out()
{
	switch (out_packet_type_)
	{
	case Out_packet_type_send_internal_rsa_pub_key :
		{
			std::vector<char> packet;
			int result = prepare_rsa_internal_pub_key_packet(packet);
			if (result == Error_no)
			{
				c_Debug() << "ProtocolParser::process_out, send RSA key\r\n";
				Net::send_data(own_node_->get_socket(), &packet[0], packet.size());

				own_node_->set_polling_flags(Net::c_poll_event_in);
			}
			break;
		}
	default:
		{
		}
	}

	own_node_->set_polling_flags(Net::c_poll_event_in);

	return Error_no;
}

void ProtocolParser::switch_to_send(Out_packet_type packet_type)
{
	out_packet_type_ = Out_packet_type_send_internal_rsa_pub_key;
	own_node_->set_polling_flags(Net::c_poll_event_out);
}
