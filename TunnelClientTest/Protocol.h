#pragma once

class TunnelClient;

class ProtocolParser
{
public:
	enum Packet_type
	{
		Packet_type_external_rsa_key = 1,
		Packet_type_login_data = 2,
		Packet_type_send_internal_rsa_pub_key = 3,
		Packet_type_login_accept = 4
	};

	enum Error
	{
		Error_wait_packet = 1,
		Error_no = 0,
		Error_crc = -1,
		Error_packet_not_complete = -2,
		Error_prepare_packet = -3,
		Error_rsa_key_packet = -4,
		Error_parse_login_packet = -5,
		Error_unknown_packet = -6,
		Error_parse_login_node_not_exist = -7
	};

	ProtocolParser(TunnelClient *own_node);
	~ProtocolParser();

	int parse_common(const std::vector<char>& data);
	void flush_common();
	void reset();
	bool is_complete() { return complete_; }

	int process_in();
	int process_out();

	int parse_external_rsa_key_packet();
	bool got_rsa_key() { return got_external_rsa_key_; }

	int prepare_packet(int packet_type, const std::vector<char>& data, std::vector<char>& out_packet) const;
	int prepare_packet(int packet_type, const std::string& data, std::vector<char>& out_packet) const;
	int prepare_rsa_internal_pub_key_packet(std::vector<char>& packet) const;

private:
	TunnelCommon::RsaCrypting rsa_crypting_;
	TunnelCommon::CRC32_hash crc_calc_;
	std::vector<char> buffer_;
	TunnelClient *own_node_;

	bool got_data_len_;
	bool got_data_;
	bool got_crc_;
	bool complete_;
	boost::uint32_t data_len_;
	std::vector<char> data_;
	boost::uint32_t crc_;

	bool got_external_rsa_key_;

	bool got_login_data_;
	std::vector<char> login_;
	std::vector<char> passwd_hash_;
	std::string node_name_;

	bool rsa_key_sent_;
};

