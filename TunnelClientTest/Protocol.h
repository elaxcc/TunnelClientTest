#pragma once

class TunnelClient;

class ProtocolParser : public TunnelCommon::Protocol
{
public:
	enum Out_packet_type
	{
		Out_packet_type_no_packet = 0,
		Out_packet_type_send_internal_rsa_pub_key = 1
	};

	ProtocolParser(TunnelClient *own_node);
	~ProtocolParser();

public: // Tunnelcommon::Protocol
	virtual int process_in();
	virtual int process_out();

	void switch_to_send(Out_packet_type packet_type);

private:
	TunnelClient *own_node_;

	Out_packet_type out_packet_type_;
};

