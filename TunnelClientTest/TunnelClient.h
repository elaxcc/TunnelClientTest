#pragma  once

#include "Protocol.h"

class TunnelClient : public Net::client
{
public:
	TunnelClient(short int initial_polling_flags_,
		bool nonblocking, bool no_nagle_delay);
	~TunnelClient();

public: // i_net_member
	virtual int process_events(short int polling_events);

private:
	ProtocolParser protocol_;
};
