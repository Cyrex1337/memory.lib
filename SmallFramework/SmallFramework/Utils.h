#pragma once

class Handle
{
private:
	HANDLE m_Handle;

public:
	Handle( ) : m_Handle( NULL ) { }

	Handle( HANDLE handle ) : m_Handle( handle ) { }

	Handle( const Handle& handle ) : m_Handle( handle.m_Handle ) { }

	Handle( Handle&& other ) : m_Handle( NULL )
	{
		m_Handle = other.m_Handle;
		other.m_Handle = NULL;
	}

	~Handle( )
	{
		CloseHandle( m_Handle );
	}
};

namespace Utils
{
	class Process
	{
	public:
		static HANDLE GetProcessHandle( const std::wstring& Process, DWORD flags = PROCESS_ALL_ACCESS )
		{
			HANDLE Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
			Handle Safe( Snapshot );
			if ( !Snapshot || Snapshot == INVALID_HANDLE_VALUE )
				return NULL;

			HANDLE ret = NULL;
			DWORD PID = 0;

			PROCESSENTRY32W curProcess;
			curProcess.dwSize = sizeof( PROCESSENTRY32W );

			HANDLE result = INVALID_HANDLE_VALUE;

			if ( Process32FirstW( Snapshot, &curProcess ) )
			{
				if ( Process == curProcess.szExeFile )
				{
					PID = curProcess.th32ProcessID;
					ret = OpenProcess( flags, FALSE, PID );
					//return ret;
					result = ret;
				}
			}

			while ( Process32NextW( Snapshot, &curProcess ) )
			{
				if ( Process == curProcess.szExeFile )
				{
					PID = curProcess.th32ProcessID;
					ret = OpenProcess( PROCESS_ALL_ACCESS, FALSE, PID );
					//return ret;
					result = ret;
				}
			}

			return result;
		}

		static DWORD GetPID( const std::wstring& Process )
		{
			HANDLE Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
			Handle Safe( Snapshot );
			if ( !Snapshot || Snapshot == INVALID_HANDLE_VALUE )
				return NULL;

			HANDLE ret = NULL;
			DWORD PID = 0;

			PROCESSENTRY32W curProcess;
			curProcess.dwSize = sizeof( PROCESSENTRY32W );

			DWORD result = 0;

			if ( Process32FirstW( Snapshot, &curProcess ) )
			{
				if ( Process == curProcess.szExeFile )
				{
					PID = curProcess.th32ProcessID;
					//return PID;
					result = PID;
				}
			}

			while ( Process32NextW( Snapshot, &curProcess ) )
			{
				if ( Process == curProcess.szExeFile )
				{
					PID = curProcess.th32ProcessID;
					//return PID;
					result = PID;
				}
			}

			return result;
		}

		static void WaitForProcess( const std::wstring& Process )
		{
			HANDLE Snapshot;
			PROCESSENTRY32W curProcess;

			while ( true )
			{
				Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
				Handle Safe( Snapshot );
				curProcess.dwSize = sizeof( PROCESSENTRY32W );

				if ( Process32FirstW( Snapshot, &curProcess ) )
					if ( Process == curProcess.szExeFile )
						break;

				while ( Process32NextW( Snapshot, &curProcess ) )
					if ( Process == curProcess.szExeFile )
						break;

				Sleep( 100 );
			}
		}

		static DWORD_PTR ProcessBase( const std::wstring& Process )
		{
			HANDLE Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetPID( Process ) );
			Handle Safe( Snapshot );
			if ( !Snapshot || Snapshot == INVALID_HANDLE_VALUE )
				return NULL;

			MODULEENTRY32W curModule;
			curModule.dwSize = sizeof( MODULEENTRY32W );

			DWORD_PTR result;

			if ( Module32FirstW( Snapshot, &curModule ) )
			{
				if ( Process == curModule.szModule )
					result = ( DWORD_PTR )curModule.modBaseAddr;
			}

			while ( Module32NextW( Snapshot, &curModule ) )
			{
				if ( Process == curModule.szModule )
					result = ( DWORD_PTR )curModule.modBaseAddr;
			}

			return result;
		}

		static DWORD_PTR ProcessSize( const std::wstring& Process )
		{
			HANDLE Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetPID( Process ) );
			Handle Safe( Snapshot );
			if ( !Snapshot || Snapshot == INVALID_HANDLE_VALUE )
				return NULL;

			MODULEENTRY32W curModule;
			curModule.dwSize = sizeof( MODULEENTRY32W );

			DWORD_PTR result = NULL;

			if ( Module32FirstW( Snapshot, &curModule ) )
			{
				if ( Process == curModule.szModule )
					result = curModule.dwSize;
			}

			while ( Module32NextW( Snapshot, &curModule ) )
			{
				if ( Process == curModule.szModule )
					result = curModule.dwSize;
			}

			return result;
		}

		static DWORD_PTR ModuleBase( const std::wstring& Process, const std::wstring& Module )
		{
			HANDLE Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetPID( Process ) );
			Handle Safe( Snapshot );
			if ( !Snapshot || Snapshot == INVALID_HANDLE_VALUE )
				return NULL;

			MODULEENTRY32W curModule;
			curModule.dwSize = sizeof( MODULEENTRY32W );

			DWORD_PTR result = NULL;

			if ( Module32FirstW( Snapshot, &curModule ) )
			{
				if ( Module == curModule.szModule )
					result = ( DWORD_PTR )curModule.modBaseAddr;
			}

			while ( Module32NextW( Snapshot, &curModule ) )
			{
				if ( Module == curModule.szModule )
					result = ( DWORD_PTR )curModule.modBaseAddr;
			}

			return result;
		}

		static DWORD_PTR ModuleSize( const std::wstring& Process, const std::wstring& Module )
		{
			HANDLE Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetPID( Process ) );
			Handle Safe( Snapshot );
			if ( !Snapshot || Snapshot == INVALID_HANDLE_VALUE )
				return NULL;

			MODULEENTRY32W curModule;
			curModule.dwSize = sizeof( MODULEENTRY32W );

			DWORD_PTR result = NULL;

			if ( Module32FirstW( Snapshot, &curModule ) )
			{
				if ( Module == curModule.szModule )
					result = curModule.dwSize;
			}

			while ( Module32NextW( Snapshot, &curModule ) )
			{
				if ( Module == curModule.szModule )
					result = curModule.dwSize;
			}

			return result;
		}
	};

	class Memory
	{
		//Removed Read-/WriteProtected because RPM
		//and WPM already deals with protection

	public:
		template <typename T>
		static T Read( const std::wstring& Process, const DWORD_PTR Address )
		{
			T ret;
			if ( !ReadProcessMemory( Process::GetProcessHandle( Process ), ( LPCVOID )Address, &ret, sizeof( T ), nullptr ) )
				return NULL;
			return ret;
		}

		template <typename T>
		static T* ReadStruct( const std::wstring& Process, const DWORD_PTR Address )
		{
			T ret;
			if ( !ReadProcessMemory( Process::GetProcessHandle( Process ), ( LPCVOID )Address, &ret, sizeof( T ), nullptr ) )
				return NULL;
			return &ret;
		}

		// ReactiioN
		template <typename T>
		static bool ReadStruct( const std::wstring& Process, const DWORD_PTR Address, T& data )
		{
			return !!ReadProcessMemory( Process::GetProcessHandle( Process ), ( LPCVOID )Address, &data, sizeof( T ), nullptr );
		}

		template <typename T>
		static T Read( HANDLE Process, const DWORD_PTR Address )
		{
			T ret;
			if ( !ReadProcessMemory( Process, ( LPCVOID )Address, &ret, sizeof( T ), nullptr ) )
				return NULL;
			return ret;
		}

		template <typename T>
		static T* Read( HANDLE Process, const DWORD_PTR Address, size_t Length )
		{
			byte* buf = ( byte* )VirtualAlloc( NULL, Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
			if ( !ReadProcessMemory( Process, ( LPCVOID )Address, buf, Length, nullptr ) )
				return NULL;
			return ( T* )buf;
		}

		template <typename T>
		static T* ReadArray( const std::wstring& Process, const DWORD_PTR Address, size_t Length )
		{
			T* buffer = new buffer[Length];
			ReadProcessMemory( Process::GetProcessHandle( Process ), ( LPCVOID )Address, buffer, Length, nullptr );
			return buffer;
		}


		template <typename T>
		static bool Write( const std::wstring& Process, const DWORD_PTR Address, T Value )
		{
			return !!WriteProcessMemory( Process::GetProcessHandle( Process ), Address, &Value, sizeof( T ), nullptr );
		}

		template <typename T>
		static bool Write( HANDLE Process, const DWORD_PTR Address, T Value )
		{
			return !!WriteProcessMemory( Process, Address, &Value, sizeof( T ), nullptr );
		}
	};

	class Pattern
	{
	public:
		#define INRANGE(x,a,b)		(x >= a && x <= b) 
		#define getBits( x )		(INRANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xa))
		#define getByte( x )		(getBits(x[0]) << 4 | getBits(x[1]))

		static DWORD_PTR CountBytes( const std::string& Pattern )
		{
			unsigned bytesCounted = 0;
			for ( unsigned it = 0; it < Pattern.size( ); ++it )
			{
				if ( Pattern[it] != '?' && Pattern[it] != ' ' && Pattern[it + 1] != '?' && Pattern[it + 1] != ' ' )
				{
					++bytesCounted;
					it += 2;
					continue;
				}

				if ( Pattern[it] == '?' && Pattern[it + 1] == ' ' )
				{
					++bytesCounted;
					it += 1;
					continue;
				}
			}

			return bytesCounted;
		}

		// "A1 ? ? ? ? BF 5D B9 5C"
		static DWORD_PTR Find( const std::string& Module, const char* Pattern )
		{
			MODULEINFO modInfo;
			if ( !GetModuleInformation( ( HANDLE )-1, GetModuleHandle( Module.c_str( ) ), &modInfo, sizeof( MODULEINFO ) ) )
				return NULL;

			unsigned int ScanSize = modInfo.SizeOfImage;

			unsigned char* code = ( unsigned char* )modInfo.lpBaseOfDll;
			unsigned short patternLength = strlen( Pattern );

			if ( Pattern[0] == ' ' )
				return NULL;

			for ( unsigned int i = 0; i < ScanSize; i++ )
			{
				for ( int j = 0, k = 0; j < patternLength && ( i + k < ScanSize ); k++ )
				{
					unsigned char tempChar[3];
					memset( tempChar, 0, sizeof( tempChar ) );

					if ( Pattern[j] == ( unsigned char )'?' )
					{
						j += 2;
						continue;
					}

					sprintf( ( char* )tempChar, "%02X", code[i + k] );

					if ( tempChar[0] != Pattern[j] ||
						tempChar[1] != Pattern[j + 1] )
						break;

					j += 3;

					if ( j > ( patternLength - 2 ) )
					{
						DWORD_PTR pointerLoc = ( ( DWORD_PTR )code + i );
						return pointerLoc;
					}
				}
			}
		}

		// "A1 ? ? ? ? BF 5D B9 5C"
		static DWORD_PTR FindEx( const std::wstring& Process, const std::wstring& Module, const char* Pattern )
		{
			DWORD_PTR Base = Process::ModuleBase( Process, Module );
			size_t Size = Process::ModuleSize( Process, Module );

			if ( !Base || !Size )
				return NULL;

			BYTE* pDataBuffer = Memory::Read<BYTE>( Process::GetProcessHandle( Process ), Base, Size );
			BYTE* found = NULL;

			size_t PatternLength = strlen( Pattern );

			if ( Pattern[0] == ' ' )
				return NULL;

			for ( int i( 0 ); i < Size; ++i )
			{
				for ( int j( 0 ), k( 0 ); j < PatternLength && ( i + k ) < Size; ++k )
				{
					unsigned char tempChar[3];
					memset( tempChar, 0, sizeof( tempChar ) );

					if ( Pattern[j] == '?' )
					{
						j += 2;
						continue;
					}

					sprintf( ( char* )tempChar, "%02X", pDataBuffer[i + k] );

					if ( tempChar[0] != Pattern[j]
						|| tempChar[1] != Pattern[j + 1] )
						break;

					j += 3;

					if ( j > ( PatternLength - 2 ) )
					{
						DWORD_PTR pointerLoc = i + Base;
						return pointerLoc;
					}
				}
			}


			return NULL;
		}

		// "A1 ? ? ? ? BF 5D B9 5C"
		static DWORD_PTR Find_V2( const std::string& Module, const char* Pattern )
		{
			auto isMatch = []( const PBYTE addr, const PBYTE pat, const PBYTE msk ) -> bool
			{
				size_t n = 0;
				while ( addr[n] == pat[n] || msk[n] == ( BYTE )'?' )
				{
					if ( !msk[++n] )
						return true;
				}
				return false;
			};

			MODULEINFO modInfo;
			if ( !GetModuleInformation( ( HANDLE )-1, GetModuleHandle( Module.c_str( ) ), &modInfo, sizeof( MODULEINFO ) ) )
				return NULL;

			PBYTE rangeStart = ( PBYTE )modInfo.lpBaseOfDll;
			DWORD len = modInfo.SizeOfImage;

			size_t l = strlen( Pattern );
			PBYTE patt_base = static_cast< PBYTE >( _alloca( l >> 1 ) );
			PBYTE msk_base = static_cast< PBYTE >( _alloca( l >> 1 ) );
			PBYTE pat = patt_base;
			PBYTE msk = msk_base;
			l = 0;
			while ( *Pattern )
			{
				if ( *( PBYTE )Pattern == ( BYTE )'\?' )
				{
					*pat++ = 0;
					*msk++ = '?';
					Pattern += ( ( *( PWORD )Pattern == ( WORD )'\?\?' ) ? 3 : 2 );
				}
				else
				{
					*pat++ = getByte( Pattern );
					*msk++ = 'x';
					Pattern += 3;
				}
				l++;
			}
			*msk = 0;
			pat = patt_base;
			msk = msk_base;
			for ( DWORD n = 0; n < ( len - l ); ++n )
			{
				if ( isMatch( rangeStart + n, patt_base, msk_base ) )
					return ( DWORD_PTR )rangeStart + n;
			}
			return NULL;
		}

		// "\xA1\x00\x00\x00\x00\xBF\x5D\x89\x5C"
		static DWORD_PTR FindRegular( const std::string& Module, PBYTE Pattern, const char* Mask )
		{
			MODULEINFO modInfo;
			if ( !GetModuleInformation( ( HANDLE )-1, GetModuleHandle( Module.c_str( ) ), &modInfo, sizeof( MODULEINFO ) ) )
				return NULL;

			for ( BYTE* region_it = ( BYTE* )modInfo.lpBaseOfDll; region_it < ( BYTE* )( DWORD )modInfo.lpBaseOfDll + modInfo.SizeOfImage; ++region_it )
			{
				if ( *region_it == *Pattern )
				{
					const unsigned char *pattern_it = ( unsigned char* )Pattern,
						*mask_it = ( unsigned char* )Mask,
						*memory_it = region_it;
					bool found = true;

					for ( ; *mask_it && ( memory_it < ( const unsigned char* )( ( DWORD )modInfo.lpBaseOfDll + modInfo.SizeOfImage ) ); ++mask_it, ++pattern_it, ++memory_it )
					{
						if ( *mask_it != 'x' ) continue;
						if ( *memory_it != *pattern_it )
						{
							found = false;
							break;
						}
					}

					if ( found ) return ( DWORD_PTR )region_it;
				}
			}
		}

		// "\xA1\x00\x00\x00\x00\xBF\x5D\x89\x5C"
		static DWORD_PTR FindRegular_V2( const std::string& Module, PBYTE Pattern, const char* Mask )
		{
			MODULEINFO modInfo;
			if ( !GetModuleInformation( ( HANDLE )-1, GetModuleHandle( Module.c_str( ) ), &modInfo, sizeof( MODULEINFO ) ) )
				return NULL;

			byte* pBaseAddress = ( byte* )modInfo.lpBaseOfDll;
			size_t nLength = modInfo.SizeOfImage;

			auto DataCompare = []( const byte* pData, const byte* mask, const char* cmask, byte chLast, size_t iEnd ) -> bool
			{
				if ( pData[iEnd] != chLast ) return false;
				for ( ; *cmask; ++cmask, ++pData, ++mask )
				{
					if ( *cmask == 'x' && *pData != *mask )
						return false;
				}

				return true;
			};

			auto iEnd = strlen( Mask ) - 1;
			auto chLast = Pattern[iEnd];

			auto* pEnd = pBaseAddress + nLength - strlen( Mask );
			for ( ; pBaseAddress < pEnd; ++pBaseAddress )
			{
				if ( DataCompare( pBaseAddress, Pattern, Mask, chLast, iEnd ) )
					return ( DWORD_PTR )pBaseAddress;
			}

			return NULL;
		}

		// "\xA1\x00\x00\x00\x00\xBF\x5D\x89\x5C"
		// x????xxxx
		static DWORD_PTR FindExRegular( const std::wstring& Process, const std::wstring& Module, BYTE* Pattern, const char* Mask )
		{
			DWORD_PTR Base = Process::ModuleBase( Process, Module );
			size_t Size = Process::ModuleSize( Process, Module );

			if ( !Base || !Size )
				return NULL;

			BYTE* pDataBuffer = Memory::Read<BYTE>( Process::GetProcessHandle( Process ), Base, Size );
			BYTE* found = NULL;

			for ( auto i( pDataBuffer ); i < pDataBuffer + Size; ++i )
			{
				for ( int iPat = 0, iMask = 0, iData = 0; Mask[iMask]; ++iPat, ++iMask, ++iData )
				{
					if ( Pattern[iPat] != pDataBuffer[( int )i + iData] && Mask[iMask] == 'x' )
						break;

					if ( Mask[iMask] == NULL )
						found = i;
				}

				if ( found )
				{
					unsigned rva = found - pDataBuffer;
					return Base + rva;
				}
			}

			return NULL;
		}
	};

	class Misc
	{
	public:
		static bool EraseHeaders( const std::wstring& Process )
		{
			DWORD dwBase = Process::ProcessBase( Process );
			PIMAGE_DOS_HEADER Dos_Header = Memory::ReadStruct<IMAGE_DOS_HEADER>( Process, Process::ProcessBase( Process ) );
			PIMAGE_NT_HEADERS pINH = Memory::ReadStruct<IMAGE_NT_HEADERS>( Process, dwBase + Dos_Header->e_lfanew );

			std::cout << "\nIMAGE_DOS_HEADER: 0x" << std::hex << dwBase << std::endl;
			std::cout << "IMAGE_NT_HEADERS: 0x" << std::hex << dwBase + Dos_Header->e_lfanew << std::endl;
			std::cout << "SizeOfHeaders: 0x" << std::hex << pINH->OptionalHeader.SizeOfHeaders << std::endl << std::endl;

			std::cout << "Sections:\n";
			auto pCurSection = ( IMAGE_SECTION_HEADER* )( dwBase + Dos_Header->e_lfanew + sizeof( IMAGE_NT_HEADERS ) );
			for ( auto i( 0 ); i < pINH->FileHeader.NumberOfSections; ++i )
			{
				auto CurSectionStruct = Memory::ReadStruct<IMAGE_SECTION_HEADER>( Process, ( DWORD_PTR )pCurSection );
				std::cout << " ------>  " << CurSectionStruct->Name << " [0x" << CurSectionStruct->VirtualAddress << "]" << std::endl;
				++pCurSection;
			}

			int buffer = 0;
			return WriteProcessMemory( Process::GetProcessHandle( Process ), ( LPVOID )dwBase, &buffer, pINH->OptionalHeader.SizeOfHeaders, nullptr );
			return true;
		}

		class Internals
		{
		public:
			static IMAGE_DOS_HEADER* GetDOSHeader( const std::wstring& Process )
			{
				IMAGE_DOS_HEADER* ret = Memory::ReadStruct<IMAGE_DOS_HEADER>( Process, Process::ProcessBase( Process ) );
				return ret;
			}

			static IMAGE_NT_HEADERS* GetNTHeaders( const std::wstring& Process )
			{
				IMAGE_NT_HEADERS* ret = Memory::ReadStruct<IMAGE_NT_HEADERS>( Process, Process::ProcessBase( Process ) + GetDOSHeader( Process )->e_lfanew );
				return ret;
			}

			static DWORD_PTR GetSectionVA( const std::wstring& Process, const std::wstring& Section )
			{
				auto SectionIt = ( IMAGE_SECTION_HEADER* )( Process::ProcessBase( Process ) + GetDOSHeader( Process )->e_lfanew + sizeof( IMAGE_NT_HEADERS ) );
				for ( auto i( 0 ); i < GetNTHeaders( Process )->FileHeader.NumberOfSections; ++i )
				{
					IMAGE_SECTION_HEADER* SectionStruct = Memory::ReadStruct<IMAGE_SECTION_HEADER>( Process, ( DWORD_PTR )SectionIt );
					if ( Section == ( const wchar_t* )SectionStruct->Name )
						return SectionStruct->VirtualAddress + Process::ProcessBase( Process );

					++SectionIt;
				}

				return NULL;
			}
		};
	};

	class Text
	{
	public:
		static size_t CountCharArray( const char* Array )
		{
			unsigned i { 0 };
			for ( ; Array[i]; ++i );
			return i;
		}

		static void RemoveFileSpecification( std::string& Path )
		{
			auto pos = Path.rfind( '\\' );
			Path = Path.substr( 0, pos + 1 );
		}

		static void FilePath( std::string& Path )
		{
			char pathz[MAX_PATH];
			GetModuleFileName( GetModuleHandle( NULL ), pathz, MAX_PATH );
			std::string nPath = std::string( pathz );
			RemoveFileSpecification( nPath );
			Path = nPath;
		}
	};

	class Allocator
	{
	public:
		DWORD_PTR Allocate( size_t Size, DWORD Protection = PAGE_EXECUTE_READWRITE, DWORD_PTR PreferredLoc = NULL )
		{
			return ( DWORD_PTR )VirtualAlloc( ( LPVOID )PreferredLoc, Size, MEM_RESERVE | MEM_COMMIT, Protection );
		}

		DWORD_PTR AllocateEx( const std::wstring& Process, size_t Size, DWORD Protection = PAGE_EXECUTE_READWRITE, DWORD_PTR PreferredLoc = NULL )
		{
			return ( DWORD_PTR )VirtualAllocEx( Process::GetProcessHandle( Process ), ( LPVOID )PreferredLoc, Size, MEM_RESERVE | MEM_COMMIT, Protection );
		}
	};
}
