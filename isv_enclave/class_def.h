class seal_data;
int global_remain=0;
unsigned char address[64];
unsigned char priv_key[64];
bool warning=0;
class trans_record{
public:
    unsigned char addr[64];
    int out_coin=0;
    //unsigned char * priv_key;
    int remaining_balance=0;
    trans_record(const unsigned char addr[64], int out){
        out_coin = out;
        for(int i=0;i<64;i++)
            this->addr[i]=addr[i];
        global_remain -= out;
        remaining_balance = global_remain;
        if(remaining_balance<0) warning=1;
    }
    trans_record(){
        for(int i=0;i<64;i++)
            this->addr[i]='*';
        out_coin=0;
        remaining_balance=0;
    }

};

////////generated after the generation of private key///////
class seal_data{
public:
    //std::vector<trans_record> trans_list;
    trans_record trans_list[10];
    int record_num=0;
    unsigned char* privkey=priv_key;
    seal_data();
};
seal_data::seal_data(){
    record_num=0;
    privkey=priv_key;
    //trans_list=new trans_record[100];

}