#include <iostream>
#include "memory.hpp"



int main(int argc, char* argv[])
{
	system("cls");
	std::cout << "md5less - early as fuck build, works, nobody gives a fuck\n\n";

	if (argv[1]) {
		if (!MD5::ChangeHash(argv[1])) {
			printf_s("[-] ChangeHash failed. \n"); // LMAO 2AM
		}
	}
	else {
		if (!MD5::ChangeHash()) {
			printf_s("[-] ChangeHash failed. \n"); // LMAO 2AM
		}
	}

	MEMORY::IterateAllProcesses();

	getchar();
	return 0;

}
