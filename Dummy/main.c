#include <Windows.h>
#include <stdio.h>

int main(void) {
	printf(
		"PID: %lu\n"
		"TID: %lu\n",
		GetCurrentProcessId(),
		GetCurrentThreadId()
	);

	while (1) {

	}
}