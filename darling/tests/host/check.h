// PASS/FAIL lines and the exit status for the host tests
int printf(const char*, ...);

static int failures;

#define CHECK(cond, ...) do { \
	int ok_ = (cond) ? 1 : 0; \
	printf("%s ", ok_ ? "PASS" : "FAIL"); \
	printf(__VA_ARGS__); \
	printf("\n"); \
	failures += !ok_; \
} while (0)

#define DONE() return failures ? 1 : 0
