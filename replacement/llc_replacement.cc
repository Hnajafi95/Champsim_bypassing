#include "cache.h"
#include <set>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map> 

#define PC_SIG_SHIFT 4
#define PC_SIG_MAX_BITS 32

int count = 0;

/*
class Info
{
public:
    uint64_t accSeq;
    uint64_t pc;
    uint64_t offset;
    uint64_t page;
    uint64_t pc_offset;
    uint64_t pc_page;
    uint64_t pc_path;
    uint64_t pc_path_offset;
    uint64_t pc_path_page;
    uint64_t bypass;
};

map<uint64_t, Info*> reuseHelper;
*/

// initialize replacement state
void CACHE::llc_initialize_replacement()
{

}

// find replacement victim
uint32_t CACHE::llc_find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set, const BLOCK *current_set, uint64_t ip, uint64_t full_addr, uint32_t type)
{
    // baseline LRU
    return lru_victim(cpu, instr_id, set, current_set, ip, full_addr, type); 
}

// called on every cache hit and cache fill
void CACHE::llc_update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way, uint64_t full_addr, uint64_t ip, uint64_t victim_addr, uint32_t type, uint8_t hit, uint32_t bypass_algorithm, uint32_t bypass)
{

    string TYPE_NAME;
    if (type == LOAD)
        TYPE_NAME = "LOAD";
    else if (type == RFO)
        TYPE_NAME = "RFO";
    else if (type == PREFETCH)
        TYPE_NAME = "PF";
    else if (type == WRITEBACK)
        TYPE_NAME = "WB";
    else
        assert(0);

    if (hit)
        TYPE_NAME += "_HIT";
    else
        TYPE_NAME += "_MISS";

    if ((type == WRITEBACK) && ip)
        assert(0);

    // uncomment this line to see the LLC accesses
    // cout << "CPU: " << cpu << "  LLC " << setw(9) << TYPE_NAME << " set: " << setw(5) << set << " way: " << setw(2) << way;
    // cout << hex << " paddr: " << setw(12) << paddr << " ip: " << setw(8) << ip << " victim_addr: " << victim_addr << dec << endl;


    if(type != WRITEBACK)
    {
	if(bypass_algorithm == 1)
	{
		total++;
		if(bypass == 1)
		{
			by_count++;
		}
		else
		{
			re_count++;
		}
	} 
   	uint64_t page = full_addr >> LOG2_PAGE_SIZE;
    	uint64_t offset = (full_addr >> LOG2_BLOCK_SIZE) & ((1ull << (LOG2_PAGE_SIZE - LOG2_BLOCK_SIZE)) - 1);
    
    	pcs.insert(ip);
    	addrs.insert(full_addr);
    	pages.insert(page);
    	offsets.insert(offset);   
    	last_pcs.push_back(ip);

    	// PC + Offset    	
    	uint64_t pc_offset_signature = ip;
    	pc_offset_signature = pc_offset_signature << 6;
    	pc_offset_signature += offset;
    	pc_offset.insert(pc_offset_signature);


    	// PC + page
    	uint64_t pc_page_signature = ip;
    	pc_page_signature = pc_page_signature << 16;
    	pc_page_signature ^= page;
    	pc_page.insert(pc_page_signature);

    	// last 4 PCs
    	/* compute signature only using last 4 PCs */
    	uint64_t pc_path_signature = 0;
    	uint64_t n = pcs.size();
    	uint64_t ptr = (n >= 4) ? (n - 4) : 0;

    	for(uint64_t index = ptr; index < last_pcs.size(); ++index)
    	{
		pc_path_signature = (pc_path_signature << PC_SIG_SHIFT);
		pc_path_signature = (pc_path_signature ^ last_pcs[index]);
    	}
    	pc_path_signature = pc_path_signature & ((1ull << PC_SIG_MAX_BITS) - 1);
    	pc_path.insert(pc_path_signature);

    	//last 4 PCs + offset
    	uint64_t pc_path_offset_signature = pc_path_signature << 6;
    	pc_path_offset_signature += offset;
    	pc_path_offset.insert(pc_path_offset_signature);    
   
    	//last 4 PCs + page
    	uint64_t pc_path_page_signature = pc_path_signature << 16;
    	pc_path_page_signature ^= page;
    	pc_path_page.insert(pc_path_page_signature);

        count++;
        //cout << count << endl;

        int reuse_distance = 0;//future reuse distance
	full_addr = full_addr >> LOG2_BLOCK_SIZE;
/*
        if(reuseHelper.find(full_addr) == reuseHelper.end())
        {
                Info *info = new Info();
                info->accSeq = count;
                info->pc = ip;
        	info->offset = offset;
		info->page = page;
		info->pc_offset = pc_offset_signature;
		info->pc_page = pc_page_signature;
		info->pc_path = pc_path_signature;
		info->pc_path_offset = pc_path_offset_signature;
		info->pc_path_page = pc_path_page_signature;
	        info->bypass = bypass;
		info->bypass_algorithm = bypass_algorithm;
		reuseHelper[full_addr] = info;
        }
        else
        {

                reuse_distance = count - reuseHelper[full_addr]->accSeq;
 		if(reuseHelper[full_addr]->bypass_algorithm == 1)
		{
	       		if(reuseHelper[full_addr]->bypass == 1)
			{
				if(reuse_distance > 32768)
				{
					accurate++;
				}
				else
				{
					inaccurate++;
				}
			}
			else
			{
				if(reuse_distance > 32768)
				{
					inaccurate++;
				}
				else
				{
					accurate++;
				}
			}
		}

		ofstream outFile;
        	outFile.open("/home/cc/champsim/offset.csv", std::ios::app);
        	outFile << " Offset: " << reuseHelper[full_addr]->offset
        	<< " Reuse_Distance: " << reuse_distance
        	<< endl;
 	      	outFile.close();
	
                outFile.open("/home/cc/champsim/page.csv", std::ios::app);
                outFile << " Page: " << reuseHelper[full_addr]->page
                << " Reuse_Distance: " << reuse_distance
                << endl;
                outFile.close();

                outFile.open("/home/cc/champsim/pc.csv", std::ios::app);
                outFile << " PC: " << reuseHelper[full_addr]->pc
                << " Reuse_Distance: " << reuse_distance
                << endl;
                outFile.close();
*/
                //outFile.open("/home/cc/champsim/pc_offset.csv", std::ios::app);
                //outFile << " PC_Offset: " << reuseHelper[full_addr]->pc_offset
                //<< " Reuse_Distance: " << reuse_distance
                //<< endl;
                //outFile.close();

                //outFile.open("/home/cc/champsim/pc_page.csv", std::ios::app);
                //outFile << " PC_Page: " << reuseHelper[full_addr]->pc_page
                //<< " Reuse_Distance: " << reuse_distance
                //<< endl;
                //outFile.close();
		
                //outFile.open("/home/cc/champsim/pc_path.csv", std::ios::app);
                //outFile << " PC_Path: " << reuseHelper[full_addr]->pc_path
                //<< " Reuse_Distance: " << reuse_distance
                //<< endl;
                //outFile.close();		

                //outFile.open("/home/cc/champsim/pc_path_offset.csv", std::ios::app);
                //outFile << " PC_Path_Offset: " << reuseHelper[full_addr]->pc_path_offset
                //<< " Reuse_Distance: " << reuse_distance
                //<< endl;
                //outFile.close();

                //outFile.open("/home/cc/champsim/pc_path_page.csv", std::ios::app);
                //outFile << " PC_Path_Page: " << reuseHelper[full_addr]->pc_path_page
                //<< " Reuse_Distance: " << reuse_distance
                //<< endl;
                //outFile.close();
/*
		Info *info = new Info();
                info->accSeq = count;
                info->pc = ip;
                info->offset = offset;
                info->page = page;
                info->pc_offset = pc_offset_signature;
                info->pc_page = pc_page_signature;
                info->pc_path = pc_path_signature;
                info->pc_path_offset = pc_path_offset_signature;
                info->pc_path_page = pc_path_page_signature;
        	info->bypass = bypass; 
	        info->bypass_algorithm = bypass_algorithm;
		reuseHelper[full_addr] = info;
	}
*/

    	//number of  hits and misses
/*
    	if(hit == 1)
    	{
		if(page_hit.find(page) == page_hit.end())
		{
			page_hit[page] = 1;	
		}
		else
		{
			page_hit[page] = page_hit[page] + 1;
		}

        	if(offset_hit.find(offset) == offset_hit.end())
        	{
                	offset_hit[offset] = 1;
        	}
        	else
        	{
                	offset_hit[offset] = offset_hit[offset] + 1;
        	}


		if(pc_hit.find(ip) == pc_hit.end())
		{
			pc_hit[ip] = 1;		
		}
		else
		{
			pc_hit[ip] = pc_hit[ip] + 1;
		}

		if(pc_offset_hit.find(pc_offset_signature) == pc_offset_hit.end())
		{
			pc_offset_hit[pc_offset_signature] = 1;
		}
		else
		{
			pc_offset_hit[pc_offset_signature] = pc_offset_hit[pc_offset_signature] + 1;
		}	

		if(pc_page_hit.find(pc_page_signature) == pc_page_hit.end())
		{
			pc_page_hit[pc_page_signature] = 1;
		}
		else
		{
			pc_page_hit[pc_page_signature] = pc_page_hit[pc_page_signature] + 1;
		}

		if(pc_path_hit.find(pc_path_signature) == pc_path_hit.end())
		{
			pc_path_hit[pc_path_signature] = 1;
		}
		else
		{
			pc_path_hit[pc_path_signature] = pc_path_hit[pc_path_signature] + 1;
		}

		if(pc_path_offset_hit.find(pc_path_offset_signature) == pc_path_offset_hit.end())
		{
			pc_path_offset_hit[pc_path_offset_signature] = 1;
		}	
		else
		{
			pc_path_offset_hit[pc_path_offset_signature] = pc_path_offset_hit[pc_path_offset_signature] + 1;
		}

		if(pc_path_page_hit.find(pc_path_page_signature) == pc_path_page_hit.end())
		{
			pc_path_page_hit[pc_path_page_signature] = 1;
		}
		else
		{
			pc_path_page_hit[pc_path_page_signature] = pc_path_page_hit[pc_path_page_signature] + 1;
		}
    	}
    	else
    	{
        	if(page_miss.find(page) == page_miss.end())
        	{
                	page_miss[page] = 1;
        	}
        	else
        	{
                	page_miss[page] = page_miss[page] + 1;
        	}

        	if(offset_miss.find(offset) == offset_miss.end())
        	{
                	offset_miss[offset] = 1;
        	}
        	else
        	{
                	offset_miss[offset] = offset_miss[offset] + 1;
        	}


        	if(pc_miss.find(ip) == pc_miss.end())
        	{
                	pc_miss[ip] = 1;
        	}
        	else
        	{
                	pc_miss[ip] = pc_miss[ip] + 1;
        	}

        	if(pc_offset_miss.find(pc_offset_signature) == pc_offset_miss.end())
        	{
                	pc_offset_miss[pc_offset_signature] = 1;
        	}
        	else
        	{
                	pc_offset_miss[pc_offset_signature] = pc_offset_miss[pc_offset_signature] + 1;
        	}

        	if(pc_page_miss.find(pc_page_signature) == pc_page_miss.end())
        	{
                	pc_page_miss[pc_page_signature] = 1;
        	}
        	else
        	{
                	pc_page_miss[pc_page_signature] = pc_page_miss[pc_page_signature] + 1;
        	}

        	if(pc_path_miss.find(pc_path_signature) == pc_path_miss.end())
        	{
                	pc_path_miss[pc_path_signature] = 1;
        	}
        	else
        	{
                	pc_path_miss[pc_path_signature] = pc_path_miss[pc_path_signature] + 1;
        	}

        	if(pc_path_offset_miss.find(pc_path_offset_signature) == pc_path_offset_miss.end())
        	{
                	pc_path_offset_miss[pc_path_offset_signature] = 1;
        	}
        	else
        	{
                	pc_path_offset_miss[pc_path_offset_signature] = pc_path_offset_miss[pc_path_offset_signature] + 1;
        	}

        	if(pc_path_page_miss.find(pc_path_page_signature) == pc_path_page_miss.end())
        	{
                	pc_path_page_miss[pc_path_page_signature] = 1;
        	}
        	else
        	{
                	pc_path_page_miss[pc_path_page_signature] = pc_path_page_miss[pc_path_page_signature] + 1;
        	}
    	}
   */
   }


    // baseline LRU
    if (hit && (type == WRITEBACK)) // writeback hit does not update LRU state
        return;
    
    if(hit)
    {
	return lru_update(set, way);
    } 
   
    if(bypass == 0)
    {
    	return lru_update(set, way);
    }
}

void CACHE::llc_replacement_final_stats()
{

}
