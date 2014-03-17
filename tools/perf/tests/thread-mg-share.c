#include "tests.h"
#include "machine.h"
#include "thread.h"
#include "map.h"

int test__thread_mg_share(void)
{
	struct machines machines;
	struct machine *machine;

	/* thread group */
	struct thread *leader;
	struct thread *t1, *t2, *t3;
	struct map_groups *mg;
	struct map_groups *mg1, *mg2, *mg3;

	/* other process */
	struct thread *other, *other_leader;
	struct map_groups *mg_other, *mg_other_leader;

	/*
	 * This test create 2 processes abstractions (struct thread)
	 * with several threads and checks they properly share and
	 * maintain map groups info (struct map_groups).
	 *
	 * thread group (pid: 0, tids: 0, 1, 2, 3)
	 * other  group (pid: 4, tids: 4, 5)
	*/

	machines__init(&machines);
	machine = &machines.host;

	/* create process with 4 threads */
	leader = machine__findnew_thread(machine, 0, 0);

	/* tests refcnt for each thread in the group */
	mg = leader->mg;
	TEST_ASSERT_VAL("wrong refcnt", mg->refcnt == 1);

	t1 = machine__findnew_thread(machine, 0, 1);

	mg1 = t1->mg;
	TEST_ASSERT_VAL("wrong refcnt", mg->refcnt == 2);

	t2 = machine__findnew_thread(machine, 0, 2);

	mg2 = t2->mg;
	TEST_ASSERT_VAL("wrong refcnt", mg->refcnt == 3);

	t3 = machine__findnew_thread(machine, 0, 3);

	mg3 = t3->mg;
	TEST_ASSERT_VAL("wrong refcnt", mg->refcnt == 4);

	/* and create 1 separated process, without thread leader */
	other = machine__findnew_thread(machine, 4, 5);

	TEST_ASSERT_VAL("failed to create threads",
			leader && t1 && t2 && t3 && other);

	/* test the map groups pointer is shared */
	TEST_ASSERT_VAL("map groups don't match", mg == mg1);
	TEST_ASSERT_VAL("map groups don't match", mg == mg2);
	TEST_ASSERT_VAL("map groups don't match", mg == mg3);

	/*
	 * Now get map groups for other thread (not thread leader)
	 * Its refcnt should be 2 because of the thread leader being
	 * included.
	 */
	mg_other = other->mg;
	TEST_ASSERT_VAL("wrong refcnt", mg_other->refcnt == 2);

	/*
	 * Verify the other leader was created by previous call.
	 * It should have shared map groups with no change in
	 * refcnt.
	 */
	other_leader = machine__find_thread(machine, 4, 4);
	TEST_ASSERT_VAL("failed to find other leader", other_leader);

	mg_other_leader = other_leader->mg;
	TEST_ASSERT_VAL("map groups don't match", mg_other_leader == mg_other);
	TEST_ASSERT_VAL("wrong refcnt", mg_other_leader->refcnt == 2);

	machine__delete_threads(machine);
	machines__exit(&machines);
	return 0;
}
