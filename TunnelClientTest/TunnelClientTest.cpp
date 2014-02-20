#include "stdafx.h"

#include "TunnelClient.h"

int _tmain(int argc, _TCHAR* argv[])
{
	Net::init();

	c_Debug() << "Test client started\r\n";

	Net::net_manager net_manager;
	TunnelClient tunnel_client(Net::c_poll_event_out, true, true);

	int res = tunnel_client.connect_to("127.0.0.1", 1234);
	if (res != Net::error_no_)
	{
		int err_code = WSAGetLastError();
		c_Debug() << "tunnel_client error connection, error == " << err_code << "\r\n";
	}
	else
	{
		c_Debug() << "tunnel_client connection ok\r\n";
	}

	net_manager.add_member(&tunnel_client);

	while (true)
	{
		net_manager.process_sockets();
	}

	return 0;
}

