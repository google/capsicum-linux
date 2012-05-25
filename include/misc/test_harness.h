/* Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * test_harness.h: simple C unit test helper.
 *                 (as bastardised to work in-kernel)
 *
 * Usage:
 *   #include "test_harness.h"
 *   TEST(standalone_test) {
 *     do_some_stuff;
 *     EXPECT_GT(10, stuff) {
 *        stuff_state_t state;
 *        enumerate_stuff_state(&state);
 *        TH_LOG("expectation failed with state: %s", state.msg);
 *     }
 *     more_stuff;
 *     ASSERT_NE(some_stuff, NULL) TH_LOG("how did it happen?!");
 *     last_stuff;
 *     EXPECT_EQ(0, last_stuff);
 *   }
 *
 *   FIXTURE(my_fixture) {
 *     mytype_t *data;
 *     int awesomeness_level;
 *   };
 *   FIXTURE_SETUP(my_fixture) {
 *     self->data = mytype_new();
 *     ASSERT_NE(NULL, self->data);
 *   }
 *   FIXTURE_TEARDOWN(my_fixture) {
 *     mytype_free(self->data);
 *   }
 *   TEST_F(my_fixture, data_is_good) {
 *     EXPECT_EQ(1, is_my_data_good(self->data));
 *   }
 *
 *   TEST_HARNESS_MAIN
 *
 * API inspired by http://code.google.com/p/googletest
 */
#ifndef TEST_HARNESS_H_
#define TEST_HARNESS_H_

#ifdef __KERNEL__
#  include <linux/string.h>
#  include <linux/printk.h>
#else
#  define _GNU_SOURCE
#  include <stdio.h>
#  include <stdlib.h>
#  include <string.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

/* All exported functionality should be declared through this macro. */
#define TEST_API(x) _##x

/*
 * Exported APIs
 */

/* TEST(name) { implementation }
 * Defines a test by name.
 * Names must be unique and tests must not be run in parallel.  The
 * implementation containing block is a function and scoping should be treated
 * as such.  Returning early may be performed with a bare "return;" statement.
 *
 * EXPECT_* and ASSERT_* are valid in a TEST() { } context.
 */
#define TEST TEST_API(TEST)

/* TEST_SIGNAL(name, signal) { implementation }
 * Defines a test by name and the expected term signal.
 * Names must be unique and tests must not be run in parallel.  The
 * implementation containing block is a function and scoping should be treated
 * as such.  Returning early may be performed with a bare "return;" statement.
 *
 * EXPECT_* and ASSERT_* are valid in a TEST() { } context.
 */
#define TEST_SIGNAL TEST_API(TEST_SIGNAL)

/* FIXTURE(datatype name) {
 *   type property1;
 *   ...
 * };
 * Defines the data provided to TEST_F()-defined tests as |self|.  It should be
 * populated and cleaned up using FIXTURE_SETUP and FIXTURE_TEARDOWN.
 */
#define FIXTURE TEST_API(FIXTURE)

/* FIXTURE_DATA(datatype name)
 * This call may be used when the type of the fixture data
 * is needed.  In general, this should not be needed unless
 * the |self| is being passed to a helper directly.
 */
#define FIXTURE_DATA TEST_API(FIXTURE_DATA)

/* FIXTURE_SETUP(fixture name) { implementation }
 * Populates the required "setup" function for a fixture.  An instance of the
 * datatype defined with _FIXTURE_DATA will be exposed as |self| for the
 * implementation.
 *
 * ASSERT_* are valid for use in this context and will prempt the execution
 * of any dependent fixture tests.
 *
 * A bare "return;" statement may be used to return early.
 */
#define FIXTURE_SETUP TEST_API(FIXTURE_SETUP)

/* FIXTURE_TEARDOWN(fixture name) { implementation }
 * Populates the required "teardown" function for a fixture.  An instance of the
 * datatype defined with _FIXTURE_DATA will be exposed as |self| for the
 * implementation to clean up.
 *
 * A bare "return;" statement may be used to return early.
 */
#define FIXTURE_TEARDOWN TEST_API(FIXTURE_TEARDOWN)

/* TEST_F(fixture, name) { implementation }
 * Defines a test that depends on a fixture (e.g., is part of a test case).
 * Very similar to TEST() except that |self| is the setup instance of fixture's
 * datatype exposed for use by the implementation.
 */
#define TEST_F TEST_API(TEST_F)

#define TEST_F_SIGNAL TEST_API(TEST_F_SIGNAL)

/* Use once to append a main() to the test file. E.g.,
 *   TEST_HARNESS_MAIN
 */
#ifdef __KERNEL__
#define TEST_HARNESS_DEBUGFS_TRIGGER TEST_API(TEST_HARNESS_DEBUGFS_TRIGGER)
#else
#define TEST_HARNESS_MAIN TEST_API(TEST_HARNESS_MAIN)
#endif

/*
 * Operators for use in TEST and TEST_F.
 * ASSERT_* calls will stop test execution immediately.
 * EXPECT_* calls will emit a failure warning, note it, and continue.
 */

/* ASSERT_EQ(expected, measured): expected == measured */
#define ASSERT_EQ TEST_API(ASSERT_EQ)
/* ASSERT_NE(expected, measured): expected != measured */
#define ASSERT_NE TEST_API(ASSERT_NE)
/* ASSERT_LT(expected, measured): expected < measured */
#define ASSERT_LT TEST_API(ASSERT_LT)
/* ASSERT_LE(expected, measured): expected <= measured */
#define ASSERT_LE TEST_API(ASSERT_LE)
/* ASSERT_GT(expected, measured): expected > measured */
#define ASSERT_GT TEST_API(ASSERT_GT)
/* ASSERT_GE(expected, measured): expected >= measured */
#define ASSERT_GE TEST_API(ASSERT_GE)
/* ASSERT_NULL(measured): NULL == measured */
#define ASSERT_NULL TEST_API(ASSERT_NULL)
/* ASSERT_TRUE(measured): measured != 0 */
#define ASSERT_TRUE TEST_API(ASSERT_TRUE)
/* ASSERT_FALSE(measured): measured == 0 */
#define ASSERT_FALSE TEST_API(ASSERT_FALSE)
/* ASSERT_STREQ(expected, measured): !strcmp(expected, measured) */
#define ASSERT_STREQ TEST_API(ASSERT_STREQ)
/* ASSERT_STRNE(expected, measured): strcmp(expected, measured) */
#define ASSERT_STRNE TEST_API(ASSERT_STRNE)
/* EXPECT_EQ(expected, measured): expected == measured */
#define EXPECT_EQ TEST_API(EXPECT_EQ)
/* EXPECT_NE(expected, measured): expected != measured */
#define EXPECT_NE TEST_API(EXPECT_NE)
/* EXPECT_LT(expected, measured): expected < measured */
#define EXPECT_LT TEST_API(EXPECT_LT)
/* EXPECT_LE(expected, measured): expected <= measured */
#define EXPECT_LE TEST_API(EXPECT_LE)
/* EXPECT_GT(expected, measured): expected > measured */
#define EXPECT_GT TEST_API(EXPECT_GT)
/* EXPECT_GE(expected, measured): expected >= measured */
#define EXPECT_GE TEST_API(EXPECT_GE)
/* EXPECT_NULL(measured): NULL == measured */
#define EXPECT_NULL TEST_API(EXPECT_NULL)
/* EXPECT_TRUE(measured): 0 != measured */
#define EXPECT_TRUE TEST_API(EXPECT_TRUE)
/* EXPECT_FALSE(measured): 0 == measured */
#define EXPECT_FALSE TEST_API(EXPECT_FALSE)
/* EXPECT_STREQ(expected, measured): !strcmp(expected, measured) */
#define EXPECT_STREQ TEST_API(EXPECT_STREQ)
/* EXPECT_STRNE(expected, measured): strcmp(expected, measured) */
#define EXPECT_STRNE TEST_API(EXPECT_STRNE)

/* TH_LOG(format, ...)
 * Optional debug logging function available for use in tests.
 * Logging may be enabled or disabled by defining TH_LOG_ENABLED.
 * E.g., #define TH_LOG_ENABLED 1
 * If no definition is provided, logging is enabled by default.
 */
#define TH_LOG  TEST_API(TH_LOG)

/*
 * Internal implementation.
 *
 */

/* Utilities exposed to the test definitions */
#ifndef TH_LOG_STREAM
#  define TH_LOG_STREAM stderr
#endif

#ifndef TH_LOG_ENABLED
#  define TH_LOG_ENABLED 1
#endif

#define _TH_LOG(fmt, ...) do { \
  if (TH_LOG_ENABLED) \
    __TH_LOG(fmt, ##__VA_ARGS__); \
} while (0)

/* Unconditional logger for internal use. */
#ifdef __KERNEL__
#  define __TH_LOG(fmt, ...) \
      printk("%s:%d:%s:" fmt "\n", \
              __FILE__, __LINE__, _metadata->name, ##__VA_ARGS__)
#else
#  define __TH_LOG(fmt, ...) \
      fprintf(TH_LOG_STREAM, "%s:%d:%s:" fmt "\n", \
              __FILE__, __LINE__, _metadata->name, ##__VA_ARGS__)
#endif

/* Defines the test function and creates the registration stub. */
#define _TEST(test_name) __TEST_IMPL(test_name, -1)

#ifndef __KERNEL__
#  define _TEST_SIGNAL(test_name, signal) __TEST_IMPL(test_name, signal)
#endif

#ifdef __KERNEL__
#  define __TEST_IMPL(test_name, _signal) \
    static void test_name(struct __test_metadata *_metadata, int *_aborted); \
    static struct __test_metadata _##test_name##_object = \
      { name: "global." #test_name, fn: &test_name, termsig: _signal }; \
    static int _register_##test_name(void) { \
      __register_test(&_##test_name##_object); \
      return 0; \
    } \
    __initcall(_register_##test_name); \
    static void test_name( \
      struct __test_metadata __attribute__((unused)) *_metadata, \
      int __attribute__((unused)) *_aborted)
#else
#  define __TEST_IMPL(test_name, _signal) \
    static void test_name(struct __test_metadata *_metadata); \
    static struct __test_metadata _##test_name##_object = \
      { name: "global." #test_name, fn: &test_name, termsig: _signal }; \
    static void __attribute__((constructor)) _register_##test_name(void) { \
      __register_test(&_##test_name##_object); \
    } \
    static void test_name( \
      struct __test_metadata __attribute__((unused)) *_metadata)
#endif

/* Wraps the struct name so we have one less argument to pass around. */
#define _FIXTURE_DATA(fixture_name) struct _test_data_##fixture_name

/* Called once per fixture to setup the data and register. */
#ifdef __KERNEL__
#  define _FIXTURE(fixture_name) \
    static int _register_##fixture_name##_data(void) { \
      __fixture_count++; \
      return 0; \
    } \
    __initcall(_register_##fixture_name##_data); \
    _FIXTURE_DATA(fixture_name)
#else
#  define _FIXTURE(fixture_name) \
    static void __attribute__((constructor)) \
        _register_##fixture_name##_data(void) { \
      __fixture_count++; \
    } \
    _FIXTURE_DATA(fixture_name)
#endif

/* Prepares the setup function for the fixture.  |_metadata| is included
 * so that ASSERT_* work as a convenience.
 */
#ifdef __KERNEL__
#define _FIXTURE_SETUP(fixture_name) \
  void fixture_name##_setup( \
    struct __test_metadata __attribute__((unused)) *_metadata, \
    _FIXTURE_DATA(fixture_name) __attribute__((unused)) *self, \
    int __attribute__((unused)) *_aborted)
#define _FIXTURE_TEARDOWN(fixture_name) \
  void fixture_name##_teardown( \
    struct __test_metadata __attribute__((unused)) *_metadata, \
    _FIXTURE_DATA(fixture_name) __attribute__((unused)) *self, \
    int __attribute__((unused)) *_aborted)
#else
#  define _FIXTURE_SETUP(fixture_name) \
    void fixture_name##_setup( \
      struct __test_metadata __attribute__((unused)) *_metadata, \
      _FIXTURE_DATA(fixture_name) __attribute__((unused)) *self)
#  define _FIXTURE_TEARDOWN(fixture_name) \
    void fixture_name##_teardown( \
      struct __test_metadata __attribute__((unused)) *_metadata, \
      _FIXTURE_DATA(fixture_name) __attribute__((unused)) *self)
#endif

/* Emits test registration and helpers for fixture-based test
 * cases.
 * TODO(wad) register fixtures on dedicated test lists.
 */
#define _TEST_F(fixture_name, test_name) \
  __TEST_F_IMPL(fixture_name, test_name, -1)

#ifndef __KERNEL__
#  define _TEST_F_SIGNAL(fixture_name, test_name, signal) \
    __TEST_F_IMPL(fixture_name, test_name, signal)
#endif

#ifdef __KERNEL__
#  define __TEST_F_IMPL(fixture_name, test_name, signal) \
    static void fixture_name##_##test_name( \
      struct __test_metadata *_metadata, \
      _FIXTURE_DATA(fixture_name) *self, \
      int *_aborted); \
    static inline void wrapper_##fixture_name##_##test_name( \
      struct __test_metadata *_metadata, \
      int *_aborted) { \
      /* fixture data is allocated, setup, and torn down per call. */ \
      _FIXTURE_DATA(fixture_name) self; \
      memset(&self, 0, sizeof(_FIXTURE_DATA(fixture_name))); \
      fixture_name##_setup(_metadata, &self, _aborted); \
      /* Let setup failure terminate early. */ \
      if (!_metadata->passed) return; \
      fixture_name##_##test_name(_metadata, &self, _aborted); \
      fixture_name##_teardown(_metadata, &self, _aborted); \
    } \
    static struct __test_metadata _##fixture_name##_##test_name##_object = { \
      name: #fixture_name "." #test_name, \
      fn: &wrapper_##fixture_name##_##test_name, \
      termsig: signal, \
     }; \
    static int _register_##fixture_name##_##test_name(void) { \
      __register_test(&_##fixture_name##_##test_name##_object); \
      return 0; \
    } \
    __initcall(_register_##fixture_name##_##test_name); \
    static void fixture_name##_##test_name( \
      struct __test_metadata __attribute__((unused)) *_metadata, \
      _FIXTURE_DATA(fixture_name) __attribute__((unused)) *self, \
      int __attribute((unused)) *_aborted)
#else
#  define __TEST_F_IMPL(fixture_name, test_name, signal) \
    static void fixture_name##_##test_name( \
      struct __test_metadata *_metadata, \
      _FIXTURE_DATA(fixture_name) *self); \
    static inline void wrapper_##fixture_name##_##test_name( \
      struct __test_metadata *_metadata) { \
      /* fixture data is allocated, setup, and torn down per call. */ \
      _FIXTURE_DATA(fixture_name) self; \
      memset(&self, 0, sizeof(_FIXTURE_DATA(fixture_name))); \
      fixture_name##_setup(_metadata, &self); \
      /* Let setup failure terminate early. */ \
      if (!_metadata->passed) return; \
      fixture_name##_##test_name(_metadata, &self); \
      fixture_name##_teardown(_metadata, &self); \
    } \
    static struct __test_metadata _##fixture_name##_##test_name##_object = { \
      name: #fixture_name "." #test_name, \
      fn: &wrapper_##fixture_name##_##test_name, \
      termsig: signal, \
     }; \
    static void __attribute__((constructor)) \
        _register_##fixture_name##_##test_name(void) { \
      __register_test(&_##fixture_name##_##test_name##_object); \
    } \
    static void fixture_name##_##test_name( \
      struct __test_metadata __attribute__((unused)) *_metadata, \
      _FIXTURE_DATA(fixture_name) __attribute__((unused)) *self)
#endif

/* Exports a simple wrapper to run the test harness. */
#ifdef __KERNEL__

static int test_harness_run(const char *name);
static ssize_t __test_run_write(struct file *file, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	char test[128];

	size_t s = min_t(size_t, count, 127);

	copy_from_user(test, ubuf, s);
	test[s] = '\0';
	if (s > 0 && test[s-1] == '\n')
		test[s-1] = '\0';

	printk(KERN_DEBUG "Running tests beginning with '%s':\n", test);
	test_harness_run(test);

	return count;
}

static struct file_operations __test_run_fops;


#define _TEST_HARNESS_DEBUGFS_TRIGGER(testname) \
static int __init __test_##testname##_init(void) \
{ \
	__test_run_fops = debugfs_file_operations; \
	__test_run_fops.write = __test_run_write; \
\
	debugfs_create_file("run_" #testname "_tests", 0644, NULL, \
		NULL, &__test_run_fops); \
\
	return 0; \
} \
__initcall(__test_##testname##_init);



#else
#  define _TEST_HARNESS_MAIN \
    int main(int argc, char **argv) { \
      return test_harness_run(argc > 1 ? argv[1] : ""); \
    }
#endif

#define _ASSERT_EQ(_expected, _seen) \
  __EXPECT(_expected, _seen, ==, 1)
#define _ASSERT_NE(_expected, _seen) \
  __EXPECT(_expected, _seen, !=, 1)
#define _ASSERT_LT(_expected, _seen) \
  __EXPECT(_expected, _seen, <, 1)
#define _ASSERT_LE(_expected, _seen) \
  __EXPECT(_expected, _seen, <=, 1)
#define _ASSERT_GT(_expected, _seen) \
  __EXPECT(_expected, _seen, >, 1)
#define _ASSERT_GE(_expected, _seen) \
  __EXPECT(_expected, _seen, >=, 1)
#define _ASSERT_NULL(_seen) \
  __EXPECT(NULL, _seen, ==, 1)

#define _ASSERT_TRUE(_seen) \
  _ASSERT_NE(0, _seen)
#define _ASSERT_FALSE(_seen) \
  _ASSERT_EQ(0, _seen)
#define _ASSERT_STREQ(_expected, _seen) \
  __EXPECT_STR(_expected, _seen, ==, 1)
#define _ASSERT_STRNE(_expected, _seen) \
  __EXPECT_STR(_expected, _seen, !=, 1)

#define _EXPECT_EQ(_expected, _seen) \
  __EXPECT(_expected, _seen, ==, 0)
#define _EXPECT_NE(_expected, _seen) \
  __EXPECT(_expected, _seen, !=, 0)
#define _EXPECT_LT(_expected, _seen) \
  __EXPECT(_expected, _seen, <, 0)
#define _EXPECT_LE(_expected, _seen) \
  __EXPECT(_expected, _seen, <=, 0)
#define _EXPECT_GT(_expected, _seen) \
  __EXPECT(_expected, _seen, >, 0)
#define _EXPECT_GE(_expected, _seen) \
  __EXPECT(_expected, _seen, >=, 0)

#define _EXPECT_NULL(_seen) \
  __EXPECT(NULL, _seen, ==, 0)
#define _EXPECT_TRUE(_seen) \
  _EXPECT_NE(0, _seen)
#define _EXPECT_FALSE(_seen) \
  _EXPECT_EQ(0, _seen)

#define _EXPECT_STREQ(_expected, _seen) \
  __EXPECT_STR(_expected, _seen, ==, 0)
#define _EXPECT_STRNE(_expected, _seen) \
  __EXPECT_STR(_expected, _seen, !=, 0)

/* Support an optional handler after and ASSERT_* or EXPECT_*.  The approach is
 * not thread-safe, but it should be fine in most sane test scenarios.
 *
 * Using __bail(), which optionally abort()s, is the easiest way to early
 * return while still providing an optional block to the API consumer.
 */
#define OPTIONAL_HANDLER(_assert) \
  for (; _metadata->trigger;  _metadata->trigger = __bail(_assert))

#define __EXPECT(_expected, _seen, _t, _assert) do { \
  /* Avoid multiple evaluation of the cases */ \
  __typeof__(_expected) __exp = (_expected); \
  __typeof__(_seen) __seen = (_seen); \
  if (!(__exp _t __seen)) { \
    unsigned long long __exp_print = 0; \
    unsigned long long __seen_print = 0; \
    /* Avoid casting complaints the scariest way we can. */ \
    memcpy(&__exp_print, &__exp, sizeof(__exp)); \
    memcpy(&__seen_print, &__seen, sizeof(__seen)); \
    __TH_LOG("Expected %s (%llu) %s %s (%llu)", \
            #_expected, __exp_print, #_t, \
            #_seen, __seen_print); \
    _metadata->passed = 0; \
    /* Ensure the optional handler is triggered */ \
    _metadata->trigger = 1; \
  } \
} while (0); OPTIONAL_HANDLER(_assert)

#define __EXPECT_STR(_expected, _seen, _t, _assert) do { \
  const char *__exp = (_expected); \
  const char *__seen = (_seen); \
  if (!(strcmp(__exp, __seen) _t 0))  { \
    __TH_LOG("Expected '%s' %s '%s'.", __exp, #_t, __seen); \
    _metadata->passed = 0; \
    _metadata->trigger = 1; \
  } \
} while (0); OPTIONAL_HANDLER(_assert)

/* Contains all the information for test execution and status checking. */
struct __test_metadata {
  const char *name;
#ifdef __KERNEL__
  void (*fn)(struct __test_metadata *, int *);
#else
  void (*fn)(struct __test_metadata *);
#endif
  int termsig;
  int passed;
  int trigger; /* extra handler after the evaluation */
  struct __test_metadata *prev, *next;
};

/* Storage for the (global) tests to be run. */
static struct __test_metadata *__test_list = NULL;
static unsigned int __test_count = 0;
static unsigned int __fixture_count = 0;

static inline void __register_test(struct __test_metadata *t) {
  __test_count++;
  /* Circular linked list where only prev is circular. */
  if (__test_list == NULL) {
    __test_list = t;
    t->next = NULL;
    t->prev = t;
    return;
  }
  t->next = NULL;
  t->prev = __test_list->prev;
  t->prev->next = t;
  __test_list->prev = t;
}

#ifndef __KERNEL__
static inline int __bail(int for_realz) {
  if (for_realz)
    abort();
  return 0;
}
#else
#define __bail(x) ({if (x) { *_aborted = 1; return; }; 0; })
#endif

#ifndef __KERNEL__
static int test_harness_run(const char * test_name) {
  struct __test_metadata *t;
  int ret = 0;
  unsigned int count = 0;
  unsigned int pass_count = 0;
  unsigned int namelen = strlen(test_name);


  /* TODO(wad) add optional arguments similar to gtest. */
  printf("[==========] Running %u tests from %u test cases.\n",
          __test_count, __fixture_count + 1);
  for (t = __test_list; t; t = t->next) {
    pid_t child_pid;
    int status;
    if (test_name != NULL && strncmp(t->name, test_name, namelen))
      continue;
    count++;
    t->passed = 1;
    t->trigger = 0;
    printf("[ RUN      ] %s\n", t->name);
    child_pid = fork();
    if (child_pid < 0) {
      printf("ERROR SPAWNING TEST CHILD\n");
      t->passed = 0;
    } else if (child_pid == 0) {
      t->fn(t);
      _exit(t->passed);
    } else {
      /* TODO(wad) add timeout support. */
      waitpid(child_pid, &status, 0);
      if (WIFEXITED(status))
        t->passed = t->termsig == -1 ? WEXITSTATUS(status) : 0;
      if (WIFSIGNALED(status)) {
        t->passed = 0;
        if (WTERMSIG(status) == SIGABRT) {
          fprintf(TH_LOG_STREAM,
                  "%s: Test terminated by assertion\n",
                 t->name);
        } else if (WTERMSIG(status) == t->termsig) {
          t->passed = 1;
        } else {
          fprintf(TH_LOG_STREAM,
                  "%s: Test terminated unexpectedly by signal %d\n",
                 t->name,
                 WTERMSIG(status));
        }
      }
    }
    printf("[     %4s ] %s\n", (t->passed ? "OK" : "FAIL"), t->name);
    if (t->passed)
      pass_count++;
    else
      ret = 1;
  }
  /* TODO(wad) organize by fixtures since ordering is not guaranteed now. */
  printf("[==========] %u / %u tests passed.\n", pass_count, count);
  printf("[  %s  ]\n", (ret ? "FAILED" : "PASSED"));
  return ret;
}
#else // __KERNEL__
static int test_harness_run(const char *test_name) {
  struct __test_metadata *t;
  int ret = 0;
  unsigned int count = 0;
  unsigned int pass_count = 0;
  unsigned int namelen = strlen(test_name);

  /* TODO(wad) add optional arguments similar to gtest. */
  printk("[==========] Running %u tests from %u test cases.\n",
          __test_count, __fixture_count + 1);
  for (t = __test_list; t; t = t->next) {
    int aborted = 0;

    if (test_name != NULL && strncmp(t->name, test_name, namelen))
      continue;

    count++;
    t->passed = 1;
    t->trigger = 0;

    printk("[ RUN      ] %s\n", t->name);

    t->fn(t, &aborted);
    if(aborted) {
      printk("%s: Test terminated by assertion\n", t->name);
      t->passed = 0;
    }

    printk("[     %4s ] %s\n", (t->passed ? "OK" : "FAIL"), t->name);

    if (t->passed)
      pass_count++;
    else
      ret = 1;
  }
  /* TODO(wad) organize by fixtures since ordering is not guaranteed now. */
  printk("[==========] %u / %u tests passed.\n", pass_count, count);
  printk("[  %s  ]\n", (ret ? "FAILED" : "PASSED"));
  return ret;
}
#endif

#endif  /* TEST_HARNESS_H_ */

