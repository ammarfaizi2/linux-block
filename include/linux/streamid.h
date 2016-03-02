#ifndef STREAMID_H
#define STREAMID_H

enum {
	STREAMID_OPEN	= 1,		/* open new stream */
	STREAMID_CLOSE	= 2,		/* close stream */
	STREAMID_GET	= 3,		/* get file/inode stream ID */

	STREAMID_F_INODE	= 1,	/* set streamid on the inode */
	STREAMID_F_FILE		= 2,	/* set streamid on the file */
};

#endif
