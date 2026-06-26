#pragma once

#ifndef SystemCodeIntegrityInformation
#define SystemCodeIntegrityInformation ((SYSTEM_INFORMATION_CLASS)103)
#endif

#ifndef CODEINTEGRITY_OPTION_TESTSIGN
#define CODEINTEGRITY_OPTION_TESTSIGN 0x02
#endif

struct system_codeintegrity_information_t {
	ULONG Length;
	ULONG CodeIntegrityOptions;
};
