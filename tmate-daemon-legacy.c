#include "tmate.h"

#define LEGACY_KEYC_NONE 0xfff
#define LEGACY_KEYC_BASE 0x1000

#define LEGACY_KEYC_ESCAPE 0x2000
#define LEGACY_KEYC_CTRL 0x4000
#define LEGACY_KEYC_SHIFT 0x8000
#define LEGACY_KEYC_PREFIX 0x10000

enum legacy_key_code {
	LEGACY_KEYC_MOUSE = LEGACY_KEYC_BASE,
	LEGACY_KEYC_BSPACE,
	LEGACY_KEYC_F1,
	LEGACY_KEYC_F2,
	LEGACY_KEYC_F3,
	LEGACY_KEYC_F4,
	LEGACY_KEYC_F5,
	LEGACY_KEYC_F6,
	LEGACY_KEYC_F7,
	LEGACY_KEYC_F8,
	LEGACY_KEYC_F9,
	LEGACY_KEYC_F10,
	LEGACY_KEYC_F11,
	LEGACY_KEYC_F12,
	LEGACY_KEYC_F13,
	LEGACY_KEYC_F14,
	LEGACY_KEYC_F15,
	LEGACY_KEYC_F16,
	LEGACY_KEYC_F17,
	LEGACY_KEYC_F18,
	LEGACY_KEYC_F19,
	LEGACY_KEYC_F20,
	LEGACY_KEYC_IC,
	LEGACY_KEYC_DC,
	LEGACY_KEYC_HOME,
	LEGACY_KEYC_END,
	LEGACY_KEYC_NPAGE,
	LEGACY_KEYC_PPAGE,
	LEGACY_KEYC_BTAB,
	LEGACY_KEYC_UP,
	LEGACY_KEYC_DOWN,
	LEGACY_KEYC_LEFT,
	LEGACY_KEYC_RIGHT,
	LEGACY_KEYC_KP_SLASH,
	LEGACY_KEYC_KP_STAR,
	LEGACY_KEYC_KP_MINUS,
	LEGACY_KEYC_KP_SEVEN,
	LEGACY_KEYC_KP_EIGHT,
	LEGACY_KEYC_KP_NINE,
	LEGACY_KEYC_KP_PLUS,
	LEGACY_KEYC_KP_FOUR,
	LEGACY_KEYC_KP_FIVE,
	LEGACY_KEYC_KP_SIX,
	LEGACY_KEYC_KP_ONE,
	LEGACY_KEYC_KP_TWO,
	LEGACY_KEYC_KP_THREE,
	LEGACY_KEYC_KP_ENTER,
	LEGACY_KEYC_KP_ZERO,
	LEGACY_KEYC_KP_PERIOD,
	LEGACY_KEYC_FOCUS_IN,
	LEGACY_KEYC_FOCUS_OUT,
};

void tmate_translate_legacy_key(int pane_id, key_code key)
{
	key_code justkey = key & KEYC_MASK_KEY;
	int lflags = 0;
	int lkey;

	if (key & KEYC_ESCAPE)	lflags |= LEGACY_KEYC_ESCAPE;
	if (key & KEYC_CTRL)	lflags |= LEGACY_KEYC_CTRL;
	if (key & KEYC_SHIFT)	lflags |= LEGACY_KEYC_SHIFT;

	switch(justkey) {
	case KEYC_BSPACE:     lkey = LEGACY_KEYC_BSPACE;	break;
	case KEYC_F1:         lkey = LEGACY_KEYC_F1;		break;
	case KEYC_F2:         lkey = LEGACY_KEYC_F2;		break;
	case KEYC_F3:         lkey = LEGACY_KEYC_F3;		break;
	case KEYC_F4:         lkey = LEGACY_KEYC_F4;		break;
	case KEYC_F5:         lkey = LEGACY_KEYC_F5;		break;
	case KEYC_F6:         lkey = LEGACY_KEYC_F6;		break;
	case KEYC_F7:         lkey = LEGACY_KEYC_F7;		break;
	case KEYC_F8:         lkey = LEGACY_KEYC_F8;		break;
	case KEYC_F9:         lkey = LEGACY_KEYC_F9;		break;
	case KEYC_F10:        lkey = LEGACY_KEYC_F10;		break;
	case KEYC_F11:        lkey = LEGACY_KEYC_F11;		break;
	case KEYC_F12:        lkey = LEGACY_KEYC_F12;		break;
	case KEYC_IC:         lkey = LEGACY_KEYC_IC;		break;
	case KEYC_DC:         lkey = LEGACY_KEYC_DC;		break;
	case KEYC_HOME:       lkey = LEGACY_KEYC_HOME;		break;
	case KEYC_END:        lkey = LEGACY_KEYC_END;		break;
	case KEYC_NPAGE:      lkey = LEGACY_KEYC_NPAGE;		break;
	case KEYC_PPAGE:      lkey = LEGACY_KEYC_PPAGE;		break;
	case KEYC_BTAB:       lkey = LEGACY_KEYC_BTAB;		break;
	case KEYC_UP:         lkey = LEGACY_KEYC_UP;		break;
	case KEYC_DOWN:       lkey = LEGACY_KEYC_DOWN;		break;
	case KEYC_LEFT:       lkey = LEGACY_KEYC_LEFT;		break;
	case KEYC_RIGHT:      lkey = LEGACY_KEYC_RIGHT;		break;
	case KEYC_KP_SLASH:   lkey = LEGACY_KEYC_KP_SLASH;	break;
	case KEYC_KP_STAR:    lkey = LEGACY_KEYC_KP_STAR;	break;
	case KEYC_KP_MINUS:   lkey = LEGACY_KEYC_KP_MINUS;	break;
	case KEYC_KP_SEVEN:   lkey = LEGACY_KEYC_KP_SEVEN;	break;
	case KEYC_KP_EIGHT:   lkey = LEGACY_KEYC_KP_EIGHT;	break;
	case KEYC_KP_NINE:    lkey = LEGACY_KEYC_KP_NINE;	break;
	case KEYC_KP_PLUS:    lkey = LEGACY_KEYC_KP_PLUS;	break;
	case KEYC_KP_FOUR:    lkey = LEGACY_KEYC_KP_FOUR;	break;
	case KEYC_KP_FIVE:    lkey = LEGACY_KEYC_KP_FIVE;	break;
	case KEYC_KP_SIX:     lkey = LEGACY_KEYC_KP_SIX;	break;
	case KEYC_KP_ONE:     lkey = LEGACY_KEYC_KP_ONE;	break;
	case KEYC_KP_TWO:     lkey = LEGACY_KEYC_KP_TWO;	break;
	case KEYC_KP_THREE:   lkey = LEGACY_KEYC_KP_THREE;	break;
	case KEYC_KP_ENTER:   lkey = LEGACY_KEYC_KP_ENTER;	break;
	case KEYC_KP_ZERO:    lkey = LEGACY_KEYC_KP_ZERO;	break;
	case KEYC_KP_PERIOD:  lkey = LEGACY_KEYC_KP_PERIOD;	break;
	case KEYC_FOCUS_IN:   lkey = LEGACY_KEYC_FOCUS_IN;	break;
	case KEYC_FOCUS_OUT:  lkey = LEGACY_KEYC_FOCUS_OUT;	break;
	default:
		if (justkey >= KEYC_BASE) {
			/* Unknown key */
			return;
		}

		if (justkey > 0x7f) {
			/* UTF8 */
			int i;
			struct utf8_data ud;
			if (utf8_split(justkey, &ud) != UTF8_DONE)
				return;

			for (i = 0; i < ud.size; i++) {
				tmate_client_legacy_pane_key(pane_id, lflags | ud.data[i]);
				lflags = 0;
			}
			return;
		}

		lkey = justkey;
	}

	tmate_client_legacy_pane_key(pane_id, lflags | lkey);
}
