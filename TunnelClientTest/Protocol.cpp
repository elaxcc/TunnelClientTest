#include "stdafx.h"

#include "Protocol.h"

#include "TunnelClient.h"

namespace
{

const std::string packet_user_accept = "Hello user!!!";

const std::string login = "user";
const std::string passwd = "passwd";
const std::string node_name;

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
						switch_to_send(Out_packet_type_login_data);
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
	case Out_packet_type_login_data :
		{
			c_Debug() << "Sending login data...";
			std::vector<char> packet;
			prepare_login_packet(login, passwd, node_name, packet);
			Net::send_data(own_node_->get_socket(), &packet[0], packet.size());

			own_node_->set_polling_flags(Net::c_poll_event_in);
			break;
		}
	default:
		{
			break;
		}
	}

	own_node_->set_polling_flags(Net::c_poll_event_in);

	return Error_no;
}

void ProtocolParser::switch_to_send(Out_packet_type packet_type)
{
	out_packet_type_ = packet_type;
	own_node_->set_polling_flags(Net::c_poll_event_out);
}

int ProtocolParser::prepare_login_packet(const std::string& login,
	const std::string& passwd, const std::string node_name, std::vector<char>& out_packet)
{
	std::vector<char> data;

	// login length
	unsigned login_size = login.size();
	for (int i = 0; i < sizeof(login_size); ++i)
	{
		char tmp = (char) (login_size >> (8 * i));
		data.push_back(tmp);
	}

	// login
	data.insert(data.end(), &login[0], &login[0] + login.size());

	// calculate password MD5 hash
	TunnelCommon::Md5_Hash md5_calc;
	md5_calc.Init();
	md5_calc.Update((char*) &passwd[0], passwd.size());
	md5_calc.Final();
	const std::vector<char>& passwd_md5_hash = md5_calc.GetHash();
	std::string passwd_md5_str = StringService::VectorCharToHexSrt(passwd_md5_hash);

	// passwd MD5 hash length
	int passed_hash_len = passwd_md5_str.size();
	for (int i = 0; i < sizeof(passed_hash_len); ++i)
	{
		char tmp = (char) (passed_hash_len >> (8 * i));
		data.push_back(tmp);
	}

	// passwd MD5 hash
	data.insert(data.end(), &passwd_md5_str[0], &passwd_md5_str[0] + passwd_md5_str.size());

	// node name length
	unsigned node_name_len = node_name.size();
	for (int i = 0; i < sizeof(node_name_len); ++i)
	{
		char tmp = (char) (node_name_len >> (8 * i));
		data.push_back(tmp);
	}

	// node name
	if (node_name_len)
	{
		data.insert(data.end(), &node_name[0], &node_name[0] + node_name.size());
	}

	return prepare_packet(TunnelCommon::Protocol::Packet_type_login_data,
		data, out_packet, true);
}
