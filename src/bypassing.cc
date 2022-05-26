#include "cache.h"
#include <cstdlib>
#include <ctime>
#include <fstream>

#define NUM_CORE NUM_CPUS
#define MAX_LLC_SETS LLC_SET
#define LLC_WAYS LLC_WAY

#define BYPASSING 1
#define REPLACEMENT 0
#define NUM_ACTIONS 2
#define NUM_PC 1024
#define NUM_PAGE 256
#define NUM_OFFSET 64
#define EQ_SIZE 512  // 2MB LLC, 32768 blocks
#define N 999999

#define IN_REWARD -10
#define REWARD 10
#define EPSILON  0.2
#define ALPHA 0.05
#define GAMMA 0.2
#define DISCOUNT 0.9999
uint32_t counter = 0;
float epsilon = EPSILON;

class State
{
public:
	uint64_t pc;
	uint64_t address;
	uint64_t page;
	uint32_t offset;
	uint32_t core;
	
	void reset()
	{
		pc = 0xdeadbeef;
		address = 0xdeadbeef;
		page = 0xdeadbeef;
		offset = 0;
		core = 0;
	}
	State(){reset();}
	~State(){}
	uint32_t value_pc()
	{
		uint32_t value = pc;
		uint32_t hashed_value = (uint32_t)(value % NUM_PC);
		return hashed_value;
	}
	
	uint32_t value_page()
        {
                uint32_t value = page;
                uint32_t hashed_value = (uint32_t)(value % NUM_PAGE);
                return hashed_value;
        }

	uint32_t value_offset()
        {
                uint32_t value = offset;
                uint32_t hashed_value = (uint32_t)(value % NUM_OFFSET);
                return hashed_value;
        }
        uint32_t value_core()
        {
                uint32_t value = core;
                uint32_t hashed_value = (uint32_t)(value % NUM_CPUS);
                return hashed_value;
        }
	std::string to_string();
};

class Naper_EQEntry
{
public:
	uint64_t address;
	State *state;
	uint32_t action; // 0: replacment, 1:  bypassing
	float reward;
	int32_t reward_type; // 0: inaccurate, 1: accurate, -1: no rewards
	bool has_reward;
	uint32_t insert_time;
	Naper_EQEntry(uint64_t ad, State *st, uint32_t ac, uint32_t in) : address(ad), state(st), action(ac), insert_time(in)
	{
		reward = 0;
		reward_type = -1;
		has_reward = false;
	}
	~Naper_EQEntry(){}
};

deque<Naper_EQEntry*> evaluation_queue;
float  q_table[NUM_CPUS][NUM_PC][NUM_OFFSET][NUM_ACTIONS];
void train(Naper_EQEntry *curr_evicted, Naper_EQEntry *last_evicted);

float update_in_reward(float in_reward, float eq_size, uint32_t age)
{
        return (float) (in_reward + 1.0 * (-1 * in_reward / eq_size) * age);
}


float update_epsilon(float epsilon, uint32_t counter)
{
       	float new_epsilon = epsilon - 0.0001 * (counter / 100);
       	if(new_epsilon < 0.02)
	{
		return 0.02;
	}
	return new_epsilon; 
}




Naper_EQEntry *last_evicted_eqentry = NULL;

void CACHE::llc_initialize_bypassing()
{
	for(uint32_t core = 0; core < NUM_CPUS; core++)
	{
		for(uint32_t pc = 0; pc < NUM_PC; pc++)
		{
			for(uint32_t offset = 0; offset < NUM_OFFSET; offset++)
			{
				for(uint32_t action = 0; action < NUM_ACTIONS; action++)
				{
					q_table[core][pc][offset][action] = 0;
				}
			}
		}
	}
}



vector<uint32_t> CACHE::llc_bypassing_decision(uint32_t cpu, uint32_t set, uint32_t way, uint64_t full_addr, uint64_t ip, uint64_t victim_addr, uint32_t type, uint8_t hit)
//uint32_t CACHE::llc_bypassing_decision(uint32_t cpu, uint32_t set, uint32_t way, uint64_t full_addr, uint64_t ip, uint64_t victim_addr, uint32_t type, uint8_t hit)
{
    counter++;
    /*
      STEP 1:
      Compute reward on demand
      if the demand address (full_addr) in the Ecaluation Queue (EQ), assign incorrect rewards
    */
    vector<Naper_EQEntry*> eqentries;
    for(uint32_t index = 0; index < evaluation_queue.size(); ++index)
    {
      if(evaluation_queue[index]->address == full_addr)
      {
        eqentries.push_back(evaluation_queue[index]);
        break;
      }
    }

    for(uint32_t index = 0; index < eqentries.size(); ++index)
    {
      Naper_EQEntry *eqentry = eqentries[index];
      uint32_t age = counter - eqentry->insert_time;
      //cout << age << endl;
      //if(eqentry->has_reward == false)
      //{
        //assign incorrect rewards
        //cout << age << endl;
	//cout << (float) (IN_REWARD + 1.0 * (-1 * (float)IN_REWARD / (float)EQ_SIZE) * age) << endl;
        float in_reward = IN_REWARD;
	float eq_size = EQ_SIZE;
	eqentry->reward += update_in_reward(in_reward, eq_size, age);
	//cout << age << endl;
	//cout << update_in_reward(in_reward, eq_size, age) << endl;
	//eqentry->reward += (float) (IN_REWARD + 1.0 * (-1 * IN_REWARD / EQ_SIZE) * age); 
        eqentry->reward_type = 0;
        eqentry->has_reward = true;
      //}
    }

    /*
      STEP 2:
      Extracts the state vector from the demand request
    */

    uint64_t page = full_addr >> LOG2_PAGE_SIZE;
    uint32_t offset = (full_addr >> LOG2_BLOCK_SIZE) & ((1ull << (LOG2_PAGE_SIZE - LOG2_BLOCK_SIZE)) - 1);
    State *state = new State();
    state->pc = ip;
    state->address = full_addr;
    state->page = page;
    state->offset = offset;
    state->core = cpu;
    /*
      STEP 3:
      Q-learning Prediction
    */
    uint64_t random_flag = 0;
    uint32_t action = 0; // default action is replacement
    // ramdom select an action
    float rand_num = rand() % (N + 1) / (float)(N + 1);
    //cout << rand_num << endl;
    //cout << epsilon << endl;
    if(rand_num < epsilon)
    //float epsilon = EPSILON;
    //if(rand_num < update_epsilon(epsilon, counter))
    {
      action = rand() % 2;
      random_flag = 1;
    }
    else
    {
      float max_q_value = -100000.0, q_value = 0.0;
      uint32_t selected_action = 0, init_index = 0;
      uint32_t pc_id = state->value_pc();
      //uint32_t page_id = state->value_page();
      uint32_t offset_id = state->value_offset();
      uint32_t core_id = state->value_core();
      //cout << "pc_id" << pc_id << endl;
      //cout << "offset_id" << offset_id << endl;
      //cout << "core_id" << core_id << endl;
      //selected_action = rand() % 2;
      for(uint32_t action_id = init_index; action_id < NUM_ACTIONS; ++action_id)
      {
        q_value = q_table[core_id][pc_id][offset_id][action_id];
	if(q_value > max_q_value)
        {
          max_q_value = q_value;
          selected_action = action_id;
        }
      }


//      if(max_q_value == 0)
//      {
        //selected_action = rand() % 2;
//        selected_action = 0;
//	random_flag = 1;
//      }

/*
      if(max_q_value == 0)
      {
	float q_value_replacement = 0;
	float q_value_bypassing = 0;
	for(uint32_t i = 0; i < 64; i++)
	{
        	q_value_replacement += q_table[core_id][pc_id][i][0];
        	q_value_bypassing += q_table[core_id][pc_id][i][1];
	}
        if(q_value_replacement > q_value_bypassing)
        {
                max_q_value = q_value_replacement;
		selected_action = 0;
        }
        else
        {
		max_q_value = q_value_bypassing;
                selected_action = 1;
        }
      }
      if(max_q_value == 0)
      {
        selected_action = rand() % 2;
      }
*/
      action = selected_action;
    }

    /*
      STEP 5:
      Inserted the evicted block (if action == 0) or bypassing block (if action == 1) into the Evaluation Queue
    */
    if(action == BYPASSING)
    {
      vector<Naper_EQEntry*> dup_eqentries;
      for(uint32_t index = 0; index < evaluation_queue.size(); ++index)
      {
        //if(evaluation_queue[index]->address == full_addr && evaluation_queue[index]->action == action)
        if(evaluation_queue[index]->address == full_addr)
	{
          dup_eqentries.push_back(evaluation_queue[index]);
          break;
        }
      }
      if(dup_eqentries.empty())
      {
        if(evaluation_queue.size() >= EQ_SIZE)
        {
          Naper_EQEntry *evicted_eqentry = NULL;
          evicted_eqentry = evaluation_queue.front();
          evaluation_queue.pop_front();
          if(last_evicted_eqentry)
          {
            train(evicted_eqentry, last_evicted_eqentry);
            delete last_evicted_eqentry->state;
            delete last_evicted_eqentry;
          }
          last_evicted_eqentry = evicted_eqentry;
        }
        Naper_EQEntry *new_eqentry = NULL;
        new_eqentry = new Naper_EQEntry(full_addr, state, action, counter);
        evaluation_queue.push_back(new_eqentry);
      }
    }
    else if (action == REPLACEMENT)
    {
      // the evicted block from LLC is block[set][way], the address is victim_addr
      vector<Naper_EQEntry*> dup_eqentries;
      for(uint32_t index = 0; index < evaluation_queue.size(); ++index)
      {
        //if(evaluation_queue[index]->address == victim_addr  && evaluation_queue[index]->action == action)
        if(evaluation_queue[index]->address == victim_addr)
	{
          dup_eqentries.push_back(evaluation_queue[index]);
          break;
        }
      }
      if(dup_eqentries.empty())
      {
        if(evaluation_queue.size() >= EQ_SIZE)
        {
          Naper_EQEntry *evicted_eqentry = NULL;
          evicted_eqentry = evaluation_queue.front();
          evaluation_queue.pop_front();
          if(last_evicted_eqentry)
          {
            train(evicted_eqentry, last_evicted_eqentry);
            delete last_evicted_eqentry->state;
            delete last_evicted_eqentry;
          }
          last_evicted_eqentry = evicted_eqentry;
        }
        Naper_EQEntry *new_eqentry = NULL;
        new_eqentry = new Naper_EQEntry(victim_addr, state, action, counter);
        evaluation_queue.push_back(new_eqentry);
      }
    }

    /*
      STEP 4:
      LLC inserts the new block (action 0, replacemnt) or bypasses the new block (action 1, bypassing)
    */

    vector<uint32_t> tmp{};
    tmp.push_back(action);
    tmp.push_back(random_flag);
    return tmp;
    //return action;
}

    /*
      STEP 6:
      Using the evicted entry from the Evaluation Queue to train the Q Table
     */
void train(Naper_EQEntry *curr_evicted, Naper_EQEntry *last_evicted)
{
  // Assign reward during eviction from Evaluation Queue
  if(last_evicted->has_reward == false)
  {
    last_evicted->reward = REWARD;
    last_evicted->reward_type = 1;
    last_evicted->has_reward = true;
  }
  // update the Q Table
  uint32_t state1_pc = last_evicted->state->value_pc();
  uint32_t state1_core = last_evicted->state->value_core();
  uint32_t state1_offset = last_evicted->state->value_offset();
  uint32_t action1 = last_evicted->action;
  int32_t reward = last_evicted->reward;
  uint32_t state2_pc =  curr_evicted->state->value_pc();
  uint32_t state2_core =  curr_evicted->state->value_core();
  uint32_t state2_offset =  curr_evicted->state->value_offset();
  uint32_t action2 = curr_evicted->action;
  float Qsa1, Qsa2;
  Qsa1 = q_table[state1_core][state1_pc][state1_offset][action1];
  Qsa2 = q_table[state2_core][state2_pc][state2_offset][action2];
  /* SARSA */
  Qsa1 = Qsa1 + ALPHA * ((float)reward + GAMMA * Qsa2 - Qsa1);
  q_table[state1_core][state1_pc][state1_offset][action1] = Qsa1;
  if (epsilon > 0.1) {
    epsilon = epsilon * DISCOUNT;
    }
  return;
}

