class Hook{
	public:
		static void __stdcall CloseUser(INT32 ClientID);
		static signed int __stdcall AcceptUser(INT32 FixClientID, const char* szIPAddress);
		static void __stdcall PacketControl(unsigned char* szBuffer, INT32 FixClientID);
};

struct PacketHeader{
	WORD Size;
	BYTE Key;
	BYTE CheckSum;
	WORD OPCode;
	WORD ClientID;
	DWORD TimeStamp;
};

struct pFDE{
	PacketHeader Header;
	char Numeric[6];
	char Unknown[10];
	int ChangeNumeric;
};

struct p20D{
	PacketHeader Header;
	char Login[16];
	char Password[12];
	INT32 Version;
	INT32 Unknows;
	char Keys[16];
};

extern char Numeric[2][101];
extern char szClientIP[128][16];

char* __stdcall GetIPFromClient(INT32 ClientID);