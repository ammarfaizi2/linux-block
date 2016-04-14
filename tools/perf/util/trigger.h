#ifndef __TRIGGER_H_
#define __TRIGGER_H_ 1

struct trigger {
	volatile enum {
		TRIGGER_OFF = -1,
		TRIGGER_DISABLED = 0,
		TRIGGER_ENABLED = 1,
	} state;
};

static inline void trigger_on(struct trigger *s)
{
	s->state = TRIGGER_DISABLED;
}

static inline void trigger_enable(struct trigger *s)
{
	if (s->state != TRIGGER_OFF)
		s->state = TRIGGER_ENABLED;
}

static inline void trigger_disable(struct trigger *s)
{
	if (s->state != TRIGGER_OFF)
		s->state = TRIGGER_DISABLED;
}

static inline bool trigger_is_enabled(struct trigger *s)
{
	if (s->state != TRIGGER_OFF)
		return s->state == TRIGGER_ENABLED;
	return false;
}

#define __TRIGGER_VAR(n) n##_state
#define __DEF_TRIGGER_VOID_FUNC(n, op)	\
static inline void n##_##op(void) {trigger_##op(&__TRIGGER_VAR(n)); }

#define __DEF_TRIGGER_FUNC(n, type, op)	\
static inline type n##_##op(void) {return trigger_##op(&__TRIGGER_VAR(n)); }

#define DEFINE_TRIGGER(n, def)				\
struct trigger n##_state = {.state = TRIGGER_##def};\
__DEF_TRIGGER_VOID_FUNC(n, on)				\
__DEF_TRIGGER_VOID_FUNC(n, enable)			\
__DEF_TRIGGER_VOID_FUNC(n, disable)			\
__DEF_TRIGGER_FUNC(n, bool, is_enabled)

#endif
