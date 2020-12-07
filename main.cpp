#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>

typedef struct SSID_arr{
	char SSID[100];
	int beacon;
}ssid_arr;
ssid_arr arr[100];
int count;
typedef struct IEEE80211_radiotap_header{
	uint8_t it_verseion;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t itpresent;
}radiotap_header;

typedef struct Beacon_Frame{
	uint8_t version:2;
	uint8_t type:2;
	uint8_t subtype:4;
	uint8_t flags;
	uint16_t duration;
	uint8_t mac1[6];
	uint8_t mac2[6];
	uint8_t mac3[6]; //bssid
	uint16_t number;
}beacon_frame;

void print_info(beacon_frame* bc_frame){
	int temp = 0;
	char* find_ssid = (char*)(bc_frame);
	find_ssid+=sizeof(beacon_frame)+12;
	char ssid[100];
	int len = (int)find_ssid[1];
	if(len !=0) memcpy(ssid,find_ssid+2,len);
	for(int i=0; i < 100; i++){
		if((strcmp(arr[i].SSID,ssid)==0)) 
		{	
			arr[i].beacon++;
			temp =1;
			printf("%02x:%02x:%02x:%02x:%02x:%02x       %d   %s\n",bc_frame->mac3[5],bc_frame->mac3[4],bc_frame->mac3[3],bc_frame->mac3[2],bc_frame->mac3[1],bc_frame->mac3[0],arr[i].beacon,arr[i].SSID);
 
			break;		
		}
		else continue;
	}
	if(temp == 0) 
	{	
		strcpy(arr[count].SSID,ssid);
		count++;
		printf("%02x:%02x:%02x:%02x:%02x:%02x       %d   %s\n",bc_frame->mac3[5],bc_frame->mac3[4],bc_frame->mac3[3],bc_frame->mac3[2],bc_frame->mac3[1],bc_frame->mac3[0],arr[count].beacon,arr[count].SSID);

			
	}



}


void usage() {
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }
    
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    printf("BSSID         Beacons   ESSID\n");

    while (true) {

        struct pcap_pkthdr* header;
        const u_char* data;
	//printf("0\n");
        int res = pcap_next_ex(handle, &header, &data);
	//printf("00\n");
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
	radiotap_header* rt_header = (radiotap_header*)data;
        beacon_frame* bc_frame = (beacon_frame*)(data+rt_header->it_len);
	if(bc_frame->type!=0 || bc_frame->subtype!=8) continue;
	
    

	print_info(bc_frame);



    }

    pcap_close(handle);
}
