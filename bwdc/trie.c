

#include <stdio.h>  
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "trie.h"

#define BUFFSIZE 60

const int lastAlocIndex = ALOCSIZE - 1;  

/* linked list of TTrieNode(s) */
typedef struct TrieNodeList {
	struct TrieNode *pNode;
	struct TrieNodeList *pNext;
	int Depth;
	int AfType;
	char *Prefix;
} TTrieNodeList;


TTrieNode *createTrieNode();
TTrieNode **lookupInTrie(unsigned char *prefix, unsigned char *byte, unsigned char *bit, unsigned char *makeMatches, TTrieNode **ppTN, bool *root);
TTrieNode *myMalloc();
int listTrieNode(TTrieNode *pTN, TTrieNodeList **plTN, const int AfType, int *depth, unsigned char *prefix);



/// Alocation speeding variables
TAlocTrieNodes *pAlocated = NULL;
TAlocTrieNodes *pActual = NULL;
struct TrieNode *pActualTN = NULL;
struct TrieNode *pLastTN = NULL;

/// IPV4 Trie
TTrieNode *pTrieIPV4 = NULL;

/// IPV6 Trie
TTrieNode *pTrieIPV6 = NULL;

/* clean tree and decrement reference count */
void freeTrieNode(TTrieNode *pTN) {
	if (pTN != NULL) {
		if (pTN->hasValue) {
			pTN->hasValue = 0;
		}
		freeTrieNode(pTN->pTN0);
		freeTrieNode(pTN->pTN1);
		free(pTN);
	}
}

/* count the number of nodes in subtree */
void countTrieNode(TTrieNode *pTN, int * totalNodes, int * valueNodes, int * trieBytes, int * dataBytes) {
	if (pTN != NULL) {
		if (pTN->hasValue) {
			(*valueNodes)++;
			(*dataBytes) += 0;
		}
		countTrieNode(pTN->pTN0, totalNodes, valueNodes, trieBytes, dataBytes);
		countTrieNode(pTN->pTN1, totalNodes, valueNodes, trieBytes, dataBytes);
		(*totalNodes)++;
		(*trieBytes) += sizeof(struct TrieNode);
	}
}

/* convert trie node into linked list  */
int listTrieNode(TTrieNode *pTN, TTrieNodeList **plTN, const int AfType, int *depth, unsigned char *prefix) {
	TTrieNodeList *ptmp;
	int allocsize;

	if (pTN != NULL) {
		if (pTN->hasValue) {
			ptmp = malloc(sizeof(TTrieNodeList));
			if (ptmp == NULL) {
				return 0;
			}
			/* get prefix len */
			allocsize = (((*depth) - 1) / 8) + 1;

			ptmp->pNext = *plTN;
			ptmp->pNode = pTN;
			ptmp->Depth = *depth;
			ptmp->AfType = AfType;
			ptmp->Prefix = malloc(allocsize);
			if (ptmp->Prefix == NULL) {
				return 0;
			}
			memcpy(ptmp->Prefix, prefix, allocsize);
			
			*plTN = ptmp;
		}
		(*depth)++;

		if (listTrieNode(pTN->pTN0, plTN, AfType, depth, prefix) == 0) return 0;

		prefix[((*depth) - 1 ) / 8] |= 0x80 >> ((((*depth) - 1) % 8) );
		if (listTrieNode(pTN->pTN1, plTN, AfType, depth, prefix) == 0) return 0;
		prefix[((*depth) - 1 ) / 8] &= 0xFF7F >> ((((*depth) - 1) % 8) );

		(*depth)--;

	}
	return 1;
}

/**
 * addPrefixToTrie adds prefix to Trie
 * prefix - prefix that will be added to Trie
 * prefixLen - prefix length
 * ASNum - number of AS
 * ppTrie - pointer at pointer of desired Trie(IPV4 or IPV6)
 * returns error if fails
 */
void addPrefixToTrie(unsigned char *prefix, unsigned char prefixLen, void * Value, TTrieNode **ppTrie){
  unsigned char byte = 0;
  unsigned char bit = 128; 
  
  unsigned char makeMatches = prefixLen;
  bool root = false;
  TTrieNode *pFound = (*ppTrie);
  TTrieNode **ppTN = lookupInTrie(prefix, &byte, &bit, &makeMatches, &pFound, &root);
  if(root){
    ppTN = ppTrie;
  }
  if(ppTN != NULL){
    while(makeMatches){
      (*ppTN) = createTrieNode();
      unsigned char unmasked = (prefix[byte] & bit);
      
      if(unmasked){
        ppTN = &((*ppTN)->pTN1);        
      }
      else{
        ppTN = &((*ppTN)->pTN0);
      }
      
      makeMatches--;
      bit = (bit >> 1);
      if(!bit){
        byte++;
        bit = 128;
      }
    }
    
    (*ppTN) = createTrieNode();
    (*ppTN)->Value = Value;
    (*ppTN)->hasValue = 1;
  }
  else{
    if(!pFound->hasValue){      
      pFound->Value = Value;
      pFound->hasValue = 1;
    }
  }
}

/**
 * createTrieNode creates Node of Trie and sets him implicitly up
 * returns NULL or created Node of Trie
 */
TTrieNode *createTrieNode(){
  //TTrieNode *pTN = myMalloc(sizeof(struct TrieNode));
  TTrieNode *pTN = malloc(sizeof(struct TrieNode));
  if(pTN == NULL){
    fprintf(stderr, "pTN malloc error.");
    return NULL;
  }
  
  // initialize
  pTN->pTN0 = NULL;
  pTN->pTN1 = NULL;
  pTN->hasValue = false;
  
  return pTN;
}


/**
 *  freeAlocTrieNodes
 *  pATN - pointer at structure to be freed  
 */ 
void freeAlocTrieNodes(TAlocTrieNodes *pATN){
  if(pATN->pNextATN != NULL){
    freeAlocTrieNodes(pATN->pNextATN);  
  }  
  free(pATN);
}

/** 
 * lookupAddressIPv6
 * address - field with address
 * addrLen - length of IP adress in bits (32 for IPv4, 128 for IPv6)
 * returns NULL when NOT match adress to any prefix in Trie
 */
TTrieNode *lookupAddress(unsigned char *address, int addrLen, TTrieNode *pTN){ 
  unsigned char byte = 0;
  unsigned char bit = 128; // most significant bit 
//  TTrieNode *pTN = pTrieIPV6;
  TTrieNode *pTNValue = NULL; 

  if (pTN == NULL) {
  	return NULL;
  }
  
  unsigned char addrPassed = 0;
  while(addrPassed++ <= addrLen){
    unsigned char unmasked = (address[byte] & bit);
    bit = (bit >> 1);    
    if(!bit){
      byte++;
      bit = 128;
    }
    
    // pTN with ASNum is desired
    if(pTN->hasValue){
      pTNValue = pTN;
    }
    
    if(unmasked){
      if(pTN->pTN1 != NULL){
        pTN = pTN->pTN1;
      }
      else{
        return pTNValue;
      }                   
    }
    else{
      if(pTN->pTN0 != NULL){
        pTN = pTN->pTN0;
      }
      else{
        return pTNValue;
      }       
    }           
  }       
  return pTNValue;
}

/** 
 * lookupInTrie
 * prefix - holds the prefix that is searched during Trie building
 * byte - byte of prefix
 * bit - bit of prefix byte
 * makeMatches - input and output,indicates prefixLen that can be used
 * ppTN - input and output, determines which Node of Trie was examined last during function proccess, at start holds the root of Trie  
 * root - return flag, true if root of Trie must be build first
 * returns NULL when match current prefix during Trie building
 */
TTrieNode **lookupInTrie(unsigned char *prefix, unsigned char *byte, unsigned char *bit, unsigned char *makeMatches, TTrieNode **ppTN, bool *root){
  if((*ppTN) == NULL){
    (*root) = true;
    return ppTN;
  }
  
  while((*makeMatches)){    
    unsigned char unmasked = (prefix[(*byte)] & (*bit));
    (*makeMatches)--;
    (*bit) = ((*bit) >> 1);
    if(!(*bit)){
      (*byte)++;
      (*bit) = 128;
    }
    
    if(unmasked){
      if((*ppTN)->pTN1 != NULL){
        (*ppTN) = (*ppTN)->pTN1;
      }
      else{
        return &((*ppTN)->pTN1);
      }                      
    }
    else{
      if((*ppTN)->pTN0 != NULL){
        (*ppTN) = (*ppTN)->pTN0;
      }
      else{
        return &((*ppTN)->pTN0);
      }    
    }           
  }
  
  (*root) = false;
  return NULL;
}

/**
 * myMalloc
 * encapsulates real malloc function but call it less times 
 * and that is why it could save some presious time
 */ 
TTrieNode *myMalloc(){
  if(pAlocated == NULL){
    pAlocated = malloc(sizeof(struct AlocTrieNodes));
    if(pAlocated == NULL){
      return NULL;
    }
    
    pAlocated->pNextATN = NULL;
    pActual = pAlocated;
    pActualTN = &pActual->TrieNodes[0];
    pLastTN = &pActual->TrieNodes[lastAlocIndex]; 
  }
  
  // Save to return it later
  TTrieNode *pReturn = pActualTN;
  
  if(pActualTN == pLastTN){
    pActual->pNextATN = malloc(sizeof(struct AlocTrieNodes));
    pActual = pActual->pNextATN;
    if(pActual == NULL){
      return NULL;
    }
    
    pActual->pNextATN = NULL;
    pActualTN = &pActual->TrieNodes[0];
    pLastTN = &pActual->TrieNodes[lastAlocIndex];
  }
  else{
    pActualTN++;
  }
  
  return pReturn;  
}


