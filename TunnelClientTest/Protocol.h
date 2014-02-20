#pragma once

class TunnelClient;

class ProtocolParser : public TunnelCommon::Protocol
{
public:
	enum Out_packet_type
	{
		Out_packet_type_no_packet = 0,
		Out_packet_type_send_internal_rsa_pub_key = 1,
		Out_packet_type_login_data = 2
	};

	ProtocolParser(TunnelClient *own_node);
	~ProtocolParser();

public: // Tunnelcommon::Protocol
	virtual int process_in();
	virtual int process_out();

	void switch_to_send(Out_packet_type packet_type);

private:
	int prepare_login_packet(const std::string& login,
		const std::string& passwd, const std::string node_name, std::vector<char>& out_packet);

	TunnelClient *own_node_;

	Out_packet_type out_packet_type_;
};

