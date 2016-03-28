#include "Includes.h"
#include "Utils.h"

// TEST 1
//int main()
/*{
	SetConsoleTitle( "########## [LOG] ##########" );
	std::cout << "Waiting for desired process...";
	Utils::Process::WaitForProcess( "notepad++.exe" );
	system( "cls" );
	HANDLE notepad = Utils::Process::GetProcessHandle( "notepad++.exe" );
	if ( !notepad || notepad == INVALID_HANDLE_VALUE )
		std::cout << "Handle to notepad.exe is invalid: " << std::hex << notepad << std::endl;
	
	std::cout << "Valid notepad handle: " << std::hex << notepad << std::endl;
	std::cout << "Notepad process id: " << std::dec << GetProcessId( notepad ) << std::endl;

	Utils::Misc::EraseHeaders( "notepad++.exe" );

	std::cout << std::endl;

	char input;
	std::cout << "Dump headers to file? [y / n]" << std::endl;
	std::cin >> input;

	if ( input == 'y' )
	{
		std::string outPath;
		Utils::Misc::FilePath( outPath );
		outPath = outPath + "header_dump.txt";
		std::ofstream header_dump( outPath );

		size_t HeaderSize = Utils::Misc::Internals::GetNTHeaders( "notepad++.exe" )->OptionalHeader.SizeOfHeaders;
		BYTE* buffer = Utils::Memory::Read<BYTE>( Utils::Process::GetProcessHandle( "notepad++.exe" ), Utils::Process::ProcessBase( "notepad++.exe" ), HeaderSize );

		for ( int i = 0; i < HeaderSize; ++i )
		{
			if ( i % 128 == 0 && i != 0 ) header_dump << std::endl;

			header_dump << std::hex << buffer[i];
		}
	}

	std::cin.get( );
	return 0;
}*/

// TEST 2
int main( )
{
	const char* carray = "fuck";

	size_t nChars = Utils::Text::CountCharArray( carray );

	std::cout << "::CountCharArray: " << nChars << std::endl;

	std::cin.get( );
	return 0;
}