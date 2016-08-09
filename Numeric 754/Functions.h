
class Functions{
	public:
		Functions();
		~Functions();
		void (*CloseUser)(INT32 ClientID);
		void (*SendClientMSG)(INT32 ClientID, const char* szMessage);
		void __stdcall Numeric754(unsigned char* szBuffer);
		void __stdcall SendPacket(INT32 ClientID, unsigned char* szBuffer, INT32 SizeOfPacket);
};
