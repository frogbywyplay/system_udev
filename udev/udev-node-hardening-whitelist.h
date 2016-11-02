#ifndef _UDEV_NODE_HARDENING_WHITELIST_
#define _UDEV_NODE_HARDENING_WHITELIST_

#include "udev-hardening-utils.h"

#ifndef END_NODE_HARDENING_WHITELIST_ELEMENT
# define END_NODE_HARDENING_WHITELIST_ELEMENT { NULL, 0000, 0, 0, 0, 0 }
#endif /* END_NODE_HARDENING_WHITELIST_ELEMENT */


#ifndef END_NODE_HARDENING_WHITELIST
# define END_NODE_HARDENING_WHITELIST(x) (x.path == NULL && x.mode == 0000)
#endif /* END_NODE_HARDENING_WHITELIST */

#ifndef WN
# define WN(node) { #node, 0000, 0, 0, 0, 0 }
#endif


struct node_hardening_whitelist_t {
	char  *path;
	mode_t mode;
	int    major;
	int    minor;
	uid_t  uid;
	gid_t  gid;
};

/* is the device allowed or not
 *
 * return: 0 = not allowed
 * otherwise = allowed
 */
static int __hardening_is_allowed_device(const char *path, const int major, const int minor, const mode_t mode, const uid_t uid, const gid_t gid);

static const struct node_hardening_whitelist_t __hardening_node_whitelist[] = {

 WN(/dev/snd/pcmC2D8p),
 WN(/dev/snd/pcmC2D7p),
 WN(/dev/snd/pcmC2D6p),
 WN(/dev/snd/pcmC2D5p),
 WN(/dev/snd/pcmC2D4p),
 WN(/dev/snd/pcmC2D3p),
 WN(/dev/snd/pcmC2D2p),
 WN(/dev/snd/pcmC2D1p),
 WN(/dev/adsp2),
 WN(/dev/snd/pcmC2D0p),
 WN(/dev/dsp2),
 WN(/dev/snd/controlC2),
 WN(/dev/audio2),
 WN(/dev/snd/pcmC3D8p),
 WN(/dev/snd/pcmC3D7p),
 WN(/dev/snd/pcmC3D6p),
 WN(/dev/snd/pcmC3D5p),
 WN(/dev/snd/pcmC3D4p),
 WN(/dev/snd/pcmC3D3p),
 WN(/dev/snd/pcmC3D2p),
 WN(/dev/snd/pcmC3D1p),
 WN(/dev/adsp3),
 WN(/dev/snd/pcmC3D0p),
 WN(/dev/dsp3),
 WN(/dev/audio3),
 WN(/dev/snd/controlC3),
 WN(/dev/snd/pcmC4D8p),
 WN(/dev/snd/pcmC4D7p),
 WN(/dev/snd/pcmC4D6p),
 WN(/dev/snd/pcmC4D5p),
 WN(/dev/snd/pcmC4D4p),
 WN(/dev/snd/pcmC4D3p),
 WN(/dev/snd/pcmC4D2p),
 WN(/dev/snd/pcmC4D1p),
 WN(/dev/snd/pcmC4D0p),
 WN(/dev/adsp4),
 WN(/dev/audio4),
 WN(/dev/dsp4),
 WN(/dev/snd/controlC4),
 WN(/dev/snd/pcmC5D8p),
 WN(/dev/snd/pcmC5D7p),
 WN(/dev/snd/pcmC5D6p),
 WN(/dev/snd/pcmC5D5p),
 WN(/dev/snd/pcmC5D4p),
 WN(/dev/snd/pcmC5D3p),
 WN(/dev/snd/pcmC5D2p),
 WN(/dev/adsp5),
 WN(/dev/snd/pcmC5D1p),
 WN(/dev/snd/pcmC5D0p),
 WN(/dev/dsp5),
 WN(/dev/audio5),
 WN(/dev/snd/controlC5),
 WN(/dev/snd/pcmC6D3p),
 WN(/dev/snd/pcmC6D2p),
 WN(/dev/snd/pcmC6D1p),
 WN(/dev/adsp6),
 WN(/dev/snd/pcmC6D0p),
 WN(/dev/dsp6),
 WN(/dev/audio6),
 WN(/dev/snd/controlC6),
	WN(/dev/mali),
	WN(/dev/i2c-1),
	WN(/dev/input/event1),
	WN(/dev/input/event2),

	WN(/dev/fb0),
	WN(/dev/fb1),
	WN(/dev/fb2),

	WN(/dev/mmcblk0),

	WN(/dev/mmcblk0p1),
	WN(/dev/mmcblk0p5),
	WN(/dev/mmcblk0p6),
	WN(/dev/mmcblk0p7),
	WN(/dev/mmcblk0p8),
	WN(/dev/mmcblk0p9),
	WN(/dev/mmcblk0p10),
	WN(/dev/mmcblk0p11),
	WN(/dev/mmcblk0p12),
	WN(/dev/mmcblk0p13),
	WN(/dev/mmcblk0p14),
	WN(/dev/mmcblk0p15),
	WN(/dev/mmcblk0p16),

	WN(/dev/mtd0),
	WN(/dev/mtd0ro),
	WN(/dev/mtdblock0),

	WN(/dev/dm-0),
	WN(/dev/dm-1),
	WN(/dev/dm-2),
	WN(/dev/dm-3),
	WN(/dev/dm-4),
	WN(/dev/dm-5),
	WN(/dev/dm-6),
	WN(/dev/dm-7),
	WN(/dev/dm-8),

	WN(/dev/media0),
	WN(/dev/loop0),
	WN(/dev/loop1),
	WN(/dev/loop2),
	WN(/dev/loop3),
	WN(/dev/loop4),
	WN(/dev/loop5),
	WN(/dev/loop6),
	WN(/dev/loop7),


	WN(/dev/rtc0),
	WN(/dev/i2c-0),

	WN(/dev/hdmi0.0),
	WN(/dev/hdcp0.0),
	WN(/dev/stm-bdispII.0.0),
	WN(/dev/stm-bdispII.1.1),

	WN(/dev/vcs),
	WN(/dev/vcs1),
	WN(/dev/vcsa),
	WN(/dev/vcsa1),

	WN(/dev/nd),
	WN(/dev/watchdog0),

	WN(/dev/console),
	WN(/dev/null),
	WN(/dev/random),
	WN(/dev/urandom),
	WN(/dev/tty),
	WN(/dev/tty0),
	WN(/dev/tty1),
	WN(/dev/tty2),
	WN(/dev/tty3),
	WN(/dev/tty4),
	WN(/dev/tty5),
	WN(/dev/tty6),
	WN(/dev/tty7),
	WN(/dev/tty8),
	WN(/dev/tty9),
	WN(/dev/ptmx),

	WN(/dev/ttyAS0),
	WN(/dev/console_tty),

	WN(/dev/nocs3_bpa2),
	WN(/dev/nocs3_tsid),
	WN(/dev/nocs3_csd),
	WN(/dev/nocs3_sec),
	WN(/dev/nocs3_cert),
	WN(/dev/crypto),


	WN(/dev/dvb),
	WN(/dev/dvb/adapter0),
	WN(/dev/dvb/adapter0/audio0),
	WN(/dev/dvb/adapter0/audio1),
	WN(/dev/dvb/adapter0/audio10),
	WN(/dev/dvb/adapter0/audio11),
	WN(/dev/dvb/adapter0/audio12),
	WN(/dev/dvb/adapter0/audio13),
	WN(/dev/dvb/adapter0/audio14),
	WN(/dev/dvb/adapter0/audio15),
	WN(/dev/dvb/adapter0/audio16),
	WN(/dev/dvb/adapter0/audio17),
	WN(/dev/dvb/adapter0/audio18),
	WN(/dev/dvb/adapter0/audio19),
	WN(/dev/dvb/adapter0/audio2),
	WN(/dev/dvb/adapter0/audio20),
	WN(/dev/dvb/adapter0/audio21),
	WN(/dev/dvb/adapter0/audio22),
	WN(/dev/dvb/adapter0/audio23),
	WN(/dev/dvb/adapter0/audio24),
	WN(/dev/dvb/adapter0/audio3),
	WN(/dev/dvb/adapter0/audio4),
	WN(/dev/dvb/adapter0/audio5),
	WN(/dev/dvb/adapter0/audio6),
	WN(/dev/dvb/adapter0/audio7),
	WN(/dev/dvb/adapter0/audio8),
	WN(/dev/dvb/adapter0/audio9),
	WN(/dev/dvb/adapter0/ca0),
	WN(/dev/dvb/adapter0/ca1),
	WN(/dev/dvb/adapter0/ca2),
	WN(/dev/dvb/adapter0/ca3),
	WN(/dev/dvb/adapter0/ca4),
	WN(/dev/dvb/adapter0/ca5),
	WN(/dev/dvb/adapter0/ca6),
	WN(/dev/dvb/adapter0/ca7),
	WN(/dev/dvb/adapter0/demux0),
	WN(/dev/dvb/adapter0/demux1),
	WN(/dev/dvb/adapter0/demux2),
	WN(/dev/dvb/adapter0/demux3),
	WN(/dev/dvb/adapter0/demux4),
	WN(/dev/dvb/adapter0/demux5),
	WN(/dev/dvb/adapter0/demux6),
	WN(/dev/dvb/adapter0/demux7),
	WN(/dev/dvb/adapter0/dvr0),
	WN(/dev/dvb/adapter0/dvr1),
	WN(/dev/dvb/adapter0/dvr2),
	WN(/dev/dvb/adapter0/dvr3),
	WN(/dev/dvb/adapter0/dvr4),
	WN(/dev/dvb/adapter0/dvr5),
	WN(/dev/dvb/adapter0/dvr6),
	WN(/dev/dvb/adapter0/dvr7),
	WN(/dev/dvb/adapter0/frontend0),
	WN(/dev/dvb/adapter0/frontend1),
	WN(/dev/dvb/adapter0/frontend2),
	WN(/dev/dvb/adapter0/frontend3),
	WN(/dev/dvb/adapter0/frontend4),
	WN(/dev/dvb/adapter0/frontend5),
	WN(/dev/dvb/adapter0/frontend6),
	WN(/dev/dvb/adapter0/frontend7),
	WN(/dev/dvb/adapter0/video0),
	WN(/dev/dvb/adapter0/video1),
	WN(/dev/dvb/adapter0/video10),
	WN(/dev/dvb/adapter0/video11),
	WN(/dev/dvb/adapter0/video12),
	WN(/dev/dvb/adapter0/video13),
	WN(/dev/dvb/adapter0/video14),
	WN(/dev/dvb/adapter0/video15),
	WN(/dev/dvb/adapter0/video16),
	WN(/dev/dvb/adapter0/video17),
	WN(/dev/dvb/adapter0/video18),
	WN(/dev/dvb/adapter0/video19),
	WN(/dev/dvb/adapter0/video2),
	WN(/dev/dvb/adapter0/video20),
	WN(/dev/dvb/adapter0/video21),
	WN(/dev/dvb/adapter0/video22),
	WN(/dev/dvb/adapter0/video23),
	WN(/dev/dvb/adapter0/video24),
	WN(/dev/dvb/adapter0/video3),
	WN(/dev/dvb/adapter0/video4),
	WN(/dev/dvb/adapter0/video5),
	WN(/dev/dvb/adapter0/video6),
	WN(/dev/dvb/adapter0/video7),
	WN(/dev/dvb/adapter0/video8),
	WN(/dev/dvb/adapter0/video9),

	WN(/dev/v4l-subdev0),
	WN(/dev/v4l-subdev1),
	WN(/dev/v4l-subdev2),
	WN(/dev/v4l-subdev3),
	WN(/dev/v4l-subdev4),
	WN(/dev/v4l-subdev5),
	WN(/dev/v4l-subdev6),
	WN(/dev/v4l-subdev7),
	WN(/dev/v4l-subdev8),
	WN(/dev/v4l-subdev9),
	WN(/dev/v4l-subdev10),
	WN(/dev/v4l-subdev11),
	WN(/dev/v4l-subdev12),
	WN(/dev/v4l-subdev13),
	WN(/dev/v4l-subdev14),
	WN(/dev/v4l-subdev15),
	WN(/dev/v4l-subdev16),

	WN(/dev/video0),
	WN(/dev/video1),
	WN(/dev/video2),
	WN(/dev/video3),
	WN(/dev/video4),

	WN(/dev/lirc0),
	WN(/dev/cec0),
	WN(/dev/h264pp),
	WN(/dev/hwrng),
	WN(/dev/sda),
	WN(/dev/sda1),
	WN(/dev/sdb),
	WN(/dev/sdb1),
	WN(/dev/sdc),
	WN(/dev/sdc1),
	WN(/dev/sdd),
	WN(/dev/sdd1),
	WN(/dev/sde),
	WN(/dev/sde1),
	WN(/dev/sdf),
	WN(/dev/sdf1),
	WN(/dev/sdg),
	WN(/dev/sdg1),
	WN(/dev/sdh),
	WN(/dev/sdh1),
	WN(/dev/sdi),
	WN(/dev/sdi1),
	WN(/dev/sdj),
	WN(/dev/sdj1),
	WN(/dev/sdk),
	WN(/dev/sdk1),
	WN(/dev/sdl),
	WN(/dev/sdl1),
	WN(/dev/sdm),
	WN(/dev/sdm1),
	WN(/dev/sdn),
	WN(/dev/sdn1),
	WN(/dev/sdo),
	WN(/dev/sdo1),
	WN(/dev/sdp),
	WN(/dev/sdp1),

	WN(/dev/opteest23100),

	END_NODE_HARDENING_WHITELIST_ELEMENT
};

static int __hardening_is_allowed_device(const char *path, const int major, const int minor, const mode_t mode, const uid_t uid, const gid_t gid)
{
	int i;

	fprintf(stderr, "###'%s' ", path);
	for(i = 0; !END_NODE_HARDENING_WHITELIST(__hardening_node_whitelist[i]); ++i){
		if( MATCH(path, __hardening_node_whitelist[i].path) ){
			fprintf(stderr, " ok\n");
			return 1;
		}
	}
	fprintf(stderr, " nok\n");
	return 0;
}

#endif /* _UDEV_NODE_HARDENING_WHITELIST_ */
