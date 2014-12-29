/* Intel HEX read/write functions, Paul Stoffregen, paul@ece.orst.edu */
/* This code is in the public domain.  Please retain my name and */
/* email address in distributed copies, and let me know about any bugs */

/* 
	==  By Hell Prototypes, http://www.hellprototypes.com/  ==
	This program was modify for only read all hex file data to g_memory[] byte by byte, 
	no segment layout, just for calculate data crc16
*/

#include <stdio.h>
#include <memory.h>

unsigned char g_memory[256*1024];		/* the g_memory is global */
int g_mem_idx = 0;

/* parses a line of intel hex code, stores the data in bytes[] */
/* and the beginning address in addr, and returns a 1 if the */
/* line was valid, or a 0 if an error occured.  The variable */
/* num gets the number of bytes that were stored into bytes[] */

int parse_hex_line(theline, bytes, addr, num, code)
char *theline;
int *addr, *num, *code;
unsigned char bytes[];
{
	int sum, len, cksum;
	char *ptr;
	
	*num = 0;
	if (theline[0] != ':') return 0;
	if (strlen(theline) < 11) return 0;
	ptr = theline+1;
	if (!sscanf(ptr, "%02x", &len)) return 0;
	ptr += 2;
	if ( strlen(theline) < (11 + (len * 2)) ) return 0;
	if (!sscanf(ptr, "%04x", addr)) return 0;
	ptr += 4;
	  /* printf("Line: length=%d Addr=%d\n", len, *addr); */
	if (!sscanf(ptr, "%02x", code)) return 0;
	ptr += 2;
	sum = (len & 255) + ((*addr >> 8) & 255) + (*addr & 255) + (*code & 255);
	while(*num != len) {
		if (!sscanf(ptr, "%02x", &bytes[*num])) return 0;
		ptr += 2;
		sum += bytes[*num] & 255;
		(*num)++;
		if (*num >= 256) return 0;
	}
	if (!sscanf(ptr, "%02x", &cksum)) return 0;
	if ( ((sum & 255) + (cksum & 255)) & 255 ) return 0; /* checksum error */
	return 1;
}

/* loads an intel hex file into the global g_memory[] array */
/* filename is a string of the file to be opened */

int load_file(filename)
char *filename;
{
	char line[512];
	FILE *fin;
	int addr, n, status;
	unsigned char bytes[256];
	int i, total=0, lineno=1;
	int minaddr=65536, maxaddr=0;

	if (strlen(filename) == 0) {
		printf("#   Can't load a file without the filename.");
		printf("#  '?' for help\n");
		return -1;
	}
	fin = fopen(filename, "r");
	if (fin == NULL) {
		printf("#   Can't open file '%s' for reading.\n", filename);
		return -2;
	}
	while (!feof(fin) && !ferror(fin)) {
		line[0] = '\0';
		fgets(line, 512, fin);
		if (line[strlen(line)-1] == '\n') line[strlen(line)-1] = '\0';
		if (line[strlen(line)-1] == '\r') line[strlen(line)-1] = '\0';
		if (parse_hex_line(line, bytes, &addr, &n, &status)) {
			if (status == 0) {  /* data */
				for(i=0; i<=(n-1); i++) {
					g_memory[g_mem_idx++] = bytes[i];
					total++;
					if (addr < minaddr) minaddr = addr;
					if (addr > maxaddr) maxaddr = addr;
					addr++;
				}
			}
			if (status == 1) {  /* end of file */
				fclose(fin);
				//printf("#   Loaded %d bytes between:", total);
				//printf(" 0x%04X to 0x%04X\n", minaddr, maxaddr);
				return 0;
			}
			if (status == 2) ;  /* begin of file */
		} else {
			printf("#   Error: '%s', line: %d\n", filename, lineno);
			fclose(fin);
			return -3;
		}
		lineno++;
	}
	
	fclose(fin);
	return -4;
}

unsigned short crc16_compute(const unsigned char * p_data, int size, const unsigned short * p_crc)
{
    int i;
    unsigned short crc = (p_crc == NULL) ? 0xffff : *p_crc;

    for (i = 0; i < size; i++)
    {
        crc  = (unsigned char)(crc >> 8) | (crc << 8);
        crc ^= p_data[i];
        crc ^= (unsigned char)(crc & 0xff) >> 4;
        crc ^= (crc << 8) << 4;
        crc ^= ((crc & 0xff) << 4) << 1;
    }

    return crc;
}

void creat_init_packet_file(const unsigned char * p_data, int size, char * filename)
{
	FILE *fout;

	unsigned short crc;
	unsigned char hardware_version[2] 		= {0xFF, 0xFF};
	unsigned char hardware_revision[2] 		= {0xFF, 0xFF};
	unsigned char application_version[4] 	= {0xFF, 0xFF, 0xFF, 0xFF};
	unsigned char softdevice_len[2] 		= {0x01, 0x00};//LSB
	unsigned char softdevice_array[2] 		= {0xFE, 0xFF};//LSB
	unsigned char crc_array[2];
	unsigned char init_packet[32];
	int           i, init_packet_idx;
	
	init_packet_idx = 0;

	if((p_data == NULL) || (size <= 0)) {
		return;
	}

	crc = crc16_compute(p_data, size, NULL);
	crc_array[0] = (unsigned char)(crc & 0xFF);//LSB
	crc_array[1] = (unsigned char)((crc>>8) & 0xFF);
	
	memcpy(&init_packet[init_packet_idx], hardware_version, sizeof(hardware_version));
	init_packet_idx += sizeof(hardware_version);
	
	memcpy(&init_packet[init_packet_idx], hardware_revision, sizeof(hardware_revision));
	init_packet_idx += sizeof(hardware_revision);
	
	memcpy(&init_packet[init_packet_idx], application_version, sizeof(application_version));
	init_packet_idx += sizeof(application_version);
	
	memcpy(&init_packet[init_packet_idx], softdevice_len, sizeof(softdevice_len));
	init_packet_idx += sizeof(softdevice_len);
	
	memcpy(&init_packet[init_packet_idx], softdevice_array, sizeof(softdevice_array));
	init_packet_idx += sizeof(softdevice_array);
	
	memcpy(&init_packet[init_packet_idx], crc_array, sizeof(crc_array));
	init_packet_idx += sizeof(crc_array);
	
	fout = fopen(filename, "w");
	if (fout == NULL) {
		printf("#   Can't creat file '%s' for writing.\n", filename);
		return;
	}
	for(i=0; i<init_packet_idx; i++) {
		fputc(init_packet[i],fout);
	}
	fclose(fout);
}

void main(int argc, char* argv[])
{
    char fileoutname[1024*2];
    int i;
	int errcode;

    argc--; argv++;

    if(argc == 0) {printf("Please feed me a hex file.\n"); exit(-1);}
   
	errcode = load_file(*argv);
    if(errcode < 0) {
		printf("*    Load file faile, error coe: %d\n", errcode);
		exit(-1);
	}

#if 0
	for(i=0; i<g_mem_idx; i++) {
		if(i%16 == 0) {
			printf("\r\n");
		}
        printf("%02x ",g_memory[i]);
	}
#endif
	
	strncpy(fileoutname, *argv, sizeof(fileoutname)-4);
	strcat(fileoutname, ".dat");
	creat_init_packet_file(g_memory, g_mem_idx, fileoutname);
}