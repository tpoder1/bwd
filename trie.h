#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define ALOCSIZE 100000



/// Structure of Node in Trie
typedef struct TrieNode{
	struct TrieNode *pTN0;
	struct TrieNode *pTN1;
	void * Value;
	int hasValue;
} TTrieNode;


/// Structure of alokated chunks of Trie Nodes
typedef struct AlocTrieNodes{
	struct TrieNode TrieNodes[ALOCSIZE];
	struct AlocTrieNodes *pNextATN;
} TAlocTrieNodes;


void addPrefixToTrie(unsigned char *prefix, unsigned char prefixLen, void * Value,  TTrieNode **ppTrie);
TTrieNode *lookupAddress(unsigned char *address, int addrLen, TTrieNode *pTN);
void freeTrieNode(TTrieNode *pTN);

