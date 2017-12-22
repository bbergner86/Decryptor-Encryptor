// Main.cpp
//

#include <windows.h>
#include <stdio.h>
#include <io.h>

//#define TEST_CODE

// Global Variables
unsigned char gkey[65537];
unsigned char *gptrKey = gkey;      // used for inline assembly routines, need to access this way for Visual Studio
char gPassword[256] = "password";
unsigned char gPasswordHash[32];
unsigned char *gptrPasswordHash = gPasswordHash;  // used for inline assembly routines, need to access this way for Visual Studio

FILE *gfptrIn = NULL;
FILE *gfptrOut = NULL;
FILE *gfptrKey = NULL;
char gInFileName[256];
char gOutFileName[256];
char gKeyFileName[256];
int gOp = 0;      // 1 = encrypt, 2 = decrypt
int gNumRounds = 1;


// Prototypes
int sha256(char *fileName, char *dataBuffer, DWORD dataLength, unsigned char sha256sum[32]);

// assembly language to count the number of ASCII letters in a data array
//  numC = number of capital letters
//  numL = number of lowercase letters
//  numO = number of characters that are not a letter
void exCountLetters( char *data, int dataLength, int *numC, int *numL, int *numO )
{
  __asm {
    cld;          // 
    push esi;       // 
    push ecx;       // 
    push ebx;
    mov esi,data;     // 
    mov ecx, dataLength;  // 

LOOP_X1:
    lodsb;          // 
    mov bl,al       // 
    push eax;       // 
    call isLetter;      // function returns a 1 in al if the character passed in is a letter, otherwise al = 0
    add esp,4       // 
    test al,al;       // 
    je lbl_OTHER;     // 

    mov al,bl       // 
    and al,0x20;      // already know it's a letter, if al == 0, then CAP
    je lbl_CAP;
    
    mov ebx,numL;     // 
    add [ebx],1;      // 
    jmp lbl_NEXT;     // 

lbl_CAP:
    mov ebx,numC;     // 
    add [ebx],1;      // 
    jmp lbl_NEXT;     // 

lbl_OTHER:
    mov ebx,numO      // 
    add [ebx],1       // 
lbl_NEXT:
    dec ecx;        // 
    jne LOOP_X1;      // 

    pop ebx;        // 
    pop ecx;        // 
    pop esi;        // 
    jmp EXIT_C_EXAMPLE;   // let C handle whatever it did upon entering this function

isLetter:
    push ebp;       // 
    mov ebp,esp;      // 
    mov al,[ebp+8];     // 
    cmp al,0x40;      // 
    ja lbl_CHK_ZU;      // check Uppercase 'Z'

lbl_RET_FALSE:
    xor eax,eax;      // 
lbl_RET:
    mov esp,ebp;      // 
    pop ebp;        // 
    ret;          // 

lbl_RET_TRUE:
    mov eax,1;        // 
    jmp lbl_RET;      // 

lbl_CHK_ZU:
    cmp al,0x5B;      // 
    jb lbl_RET_TRUE;    // 

    cmp al,0x61;      // 
    jb lbl_RET_FALSE;   // check lowercase 'z'

    cmp al,0x7A;      // 
    jbe lbl_RET_TRUE;   // 
    jmp lbl_RET_FALSE;    // 

  } // end assembly block

EXIT_C_EXAMPLE:         // 
  return;
} // exCountLetters

//////////////////////////////////////////////////////////////////////////////////////////////////
// code to encrypt the data as specified by the project assignment
void encryptData(char *data, int len)
{

  __asm {
    push  eax                           // Store previous values of eax, ebx,
    push  ebx                           // ecx, and edx
    push  ecx
    push  edx

  STACK_FRAME: 
    // push  ebp                         // Setup stack frame and allocate
    // mov   ebp, esp                    // enough memory for local vars.
    sub   esp, 0x38                      // Make space for local variables

  LOCAL_VARS:
    mov   eax, gNumRounds               // Move global vars into local vars
    mov   ebx, gptrPasswordHash
    mov   ecx, len            
    mov   edx, data

    mov   [ebp -  4], eax               // int rounds  = gNumRounds
    mov   [ebp -  8], ebx               // char *pHash = gptrPasswordHash
    mov   [ebp - 12], ecx               // int length
    mov   [ebp - 16], edx               // char *file  = data
    xor   ecx, ecx                      // Zero out ecx
    mov   [ebp - 20], ecx               // int currRound = 0

    mov   eax, gptrKey
    mov   [ebp - 40], ecx               // int x = 0
    // [ebp - 44] to [ebp - 52] are in the FILE LOOP
    mov   [ebp - 56], eax               // char *key = gPtrKey
  
                  

  ROUND_LOOP:
    mov   ecx,  0x0                     // Set ecx to 
							 // 0 to calc indexes

    // EBX will store the offset for our starting points.
    // Ex. [0 + round * 4], etc...
  
  STARTING_POINTS:
    xor   eax, eax                      // Clear out eax
    mov   esi, [ebp -  8]               // esi = pHash
    mov    dx, 0x100                    // edx = 256
    movzx edx,  dx

    mov   ebx, [ebp - 20]               // ebx = currRound
    shl   ebx, 0x2                      // ebx *= 4

    add   ebx, ecx                       
    inc   ecx                           // ecx += 1
    mov    al, [esi][ebx]               // eax = 
							 // pHash[0 + round * 4]

    mul   edx                           // eax * 256

    mov   ebx, [ebp - 20]               // ebx = currRound
    shl   ebx, 0x2                      // ebx *= 4

    add   ebx, ecx                      // ebx += 1
    inc   ecx
    add    al, [esi][ebx]               // eax = 
							 // pHash[1 + round * 4]
    //mov   esi, [ebp - 56]
  
  // Repeat the above code for idx1, idx2, hop1, hop2
  IDXS:
    cmp   ecx, 0x2 
    je    IDX_1

    cmp   ecx, 0x6
    je    IDX_2

    jmp   HOP_OVERFLOW                  // The rest are hops. 
							 // Ensure != 0

  HOPS:
    cmp   ecx, 0x4
    je    HOP_1

    cmp   ecx, 0x8
    je    HOP_2

  IDX_1:
    mov   [ebp - 24], eax               // int idx1 = eax
    jmp   STARTING_POINTS

  HOP_1:
    mov   [ebp - 28], eax               // int hop1 = eax
    jmp   STARTING_POINTS

  IDX_2:
    mov   [ebp - 32], eax               // int idx2 = eax
    jmp   STARTING_POINTS

  HOP_2:
    mov   [ebp - 36], eax               // int hop2 = eax
    jmp   FILE_SETUP

  HOP_OVERFLOW:
    cmp   ecx, 0                        // if hop == 0
							 //  then hop = 0xFFFF
    je    HOP_OVERFLOW_FIX
    jmp   HOP_OVERFLOW_RETN

  HOP_OVERFLOW_FIX:
    mov   ecx, 0xFFFF

  HOP_OVERFLOW_RETN:
    jmp   HOPS

  FILE_SETUP:
    mov   edi, [ebp - 16]               // edi = file
    mov   esi, [ebp - 56]               // esi = gptrKey
    
  FILE_LOOP:
    mov   edx, [ebp - 24]               // edx = idx1
    mov   ecx, [ebp - 40]               // ecx = x

    mov    al, [edi][ecx]               //  al = file[x]
    mov    bl, [esi][edx]               //  bl = key[idx1]
    xor    al, bl                       // file[x] = file[x] ^ key[idx1]

    mov   ebx, [ebp - 28]               // ebx = hop1
    add   edx, ebx                      // idx1 + hop1
    cmp   edx, 0x10001                  // idx == 0x10001
    jbe   STORE_IDX1                    // skip if idx != 0x1001
    sub   edx, 0x10001

  STORE_IDX1:
    mov   [ebp - 24], edx               // idx1 = edx

    mov   [ebp - 44], 0x01              // count1
    mov   [ebp - 48], 0x07              // shifting count
    mov   [ebp - 52], 0x80              // count2

  SWAP_NIBBLES:
    ror   al, 0x05                      // rotate 1 bit to the 
							 // right and swap nibbles

    // set up counts and push registers for use for reversing bits
    push  ecx
    push  ebx
    mov   cl, [ebp - 48]                // Store shift count in cl
    mov   bl, 0x7F                      // bl = 127, 0111 1111
    mov   ch, 0xFE                      // ch = 254, 1111 1110

  REVERSE_BITS:
    mov   ah, al                        // Shift al to ah 
    and   ah, [ebp - 44]                // mask off right most bit
    and   al, ch                        // delete masked off bit 
							 // from al

    rol   ch, 1                         // prepare count 
							 // for next loop

    shl   ah, cl                        // move masked off bit
							 // to appropriate position

    mov   bh, ah                        // Store in bh
    mov   ah, al                        // move al to ah
    and   ah, [ebp - 52]                // mask left most bit
    and   al, bl                        // delete masked off bit
    ror   bl, 1                         // prepare count 
							 // for next loop

    shr   ah, cl					 // move masked off bit
							 // to appropriate position

    or    bh, ah					 // put masked off 
							 // bits together

    or    al, bh					 // restore swapped
							 // bits to al

    mov   ah, [ebp - 44]                // manipulate counts
    shl   ah, 1
    mov   [ebp - 44], ah
    sub   cl, 2
    mov   ah, [ebp - 52]
    shr   ah, 1
    mov   [ebp - 52], ah
    cmp   ah, 0x10                      // if equal then do last 
							 // iteration of loop

    jge   REVERSE_BITS
    pop   ebx
    pop   ecx
    
    // code to swap half nibbles
    mov   ah, al                        // store al in ah
    and   ah, 0x03                      // get first 2 bits
    shl   ah, 0x02                      // shift left 2 spaces
    mov   bh, al                        // store al in bh
    and   bh, 0x0C                      // get second 2 bits
    shr   bh, 0x02                      // shift right 2 spaces
    or    bh, ah                        // combine bits
    mov   ah, al                        // store al in ah
    mov   al, bh                        // move bh to al
    mov   bh, ah                        // store original al to bh
    and   ah, 0x30                      // get third 2 bits
    shl   ah, 0x02                      // shift left 2 spaces
    and   bh, 0xC0                      // get last 2 bits
    shr   bh, 0x02                      // shift right 2 spaces
    or    bh, ah                        // combine bits
    or    al, bh                        // combine back together

    rol   al, 0x01                      // rotate left one bit
    // END OF SWAP CODE
  
    mov   edx, [ebp - 32]               // edx = idx2
    mov   ecx, [ebp - 40]               // ecx = x

    mov    bl, [esi][edx]               //  bl = key[idx2]
    xor    al, bl                       // file[x] ^ key[idx2]
    mov   [edi][ecx], al                // Store al back into data

    mov   ebx, [ebp - 36]               // ebx = hop2
    add   edx, ebx                      // idx2 + hop2
    cmp   edx, 0x10001                  // idx == 0x10001
    jbe   STORE_IDX2                    // skip if idx != 0x1001
    sub   edx, 0x10001

  STORE_IDX2:
    mov   [ebp - 32], edx               // idx2 = edx

  FILE_LOOP_INC:
    mov   ecx, [ebp - 40]               // ecx = x
    inc   ecx                           // x++
    mov   [ebp - 40], ecx               // x = ecx

    cmp   ecx, [ebp - 12]               // x == len ?
    jnz   FILE_LOOP                     // nope. Continue looping
    je    ROUND_INC                     // yes. Increase round
    

  ROUND_INC:
    mov   ecx, [ebp - 20]               // ecx = currRound
    inc   ecx                           // ecx++
    mov   [ebp - 20], ecx               // currRound = ecx

    cmp   ecx, [ebp -  4]               // currRound == gNumRound?
    mov   [ebp - 40], 0x0               // x = 0. Eagerly assigned.
    jnz   ROUND_LOOP                    // currRound != gNumRound.
    je    FINISH                        // currRound == gNumRound. Exit.

  FINISH:
    add   esp, 0x38                     // Destroy locals

    pop   edx
    pop   ecx
    pop   ebx
    pop   eax
  }

EXIT_C_ENCRYPT_DATA:
  return;
} // encryptData

// code to read the file to encrypt
int encryptFile(FILE *fptrIn, FILE *fptrOut)
{
  char *buffer;
  unsigned int filesize;

  filesize = _filelength(_fileno(fptrIn));  // Linux???
  if(filesize > 0x1000000)          // 16 MB, file too large
  {
    fprintf(stderr, "Error - Input file too large.\n\n");
    return -1;
  }

  // use the password hash to encrypt
  buffer = (char *) malloc(filesize);
  if(buffer == NULL)
  {
    fprintf(stderr, "Error - Could not allocate %d bytes of memory on the heap.\n\n", filesize);
    return -1;
  }

  fread(buffer, 1, filesize, fptrIn); // read entire file
  encryptData(buffer, filesize);
  fwrite(buffer, 1, filesize, fptrOut);
  free(buffer);

  return 0;
} // encryptFile

//////////////////////////////////////////////////////////////////////////////////////////////////
// code to decrypt the data as specified by the project assignment
void decryptData(char *data, int len)
{
  // you can not declare any local variables in C, set up the stack frame and 
  // assign them in assembly
  __asm {
    push  eax                           // Store previous values of eax, ebx,
    push  ebx                           // ecx, and edx
    push  ecx
    push  edx

  STACK_FRAME :
    // push  ebp                        // Setup stack frame and allocate
    // mov   ebp, esp                   // enough memory for local vars.
    sub   esp, 0x38                     

  LOCAL_VARS :
    mov   eax, gNumRounds               // Move global vars into local vars
    mov   ebx, gptrPasswordHash
    mov   ecx, len
    mov   edx, data

    mov  [ebp - 4], eax                 // int rounds  = gNumRounds
    mov  [ebp - 8], ebx                 // char *pHash = gptrPasswordHash
    mov  [ebp - 12], ecx                // int length
    mov  [ebp - 16], edx                // char *file  = data
    xor   ecx, ecx                      // Clear out ecx
    dec   eax                           // round--; Ex. gNumRounds = 3? rounds = 2
    mov  [ebp - 20], eax                // int currRound = gNumRounds - 1

    mov   eax, gptrKey                  // eax = gPtrKey
    mov  [ebp - 40], ecx                // int x = 0

    // [ebp - 44] to [ebp - 52] are in the FILE LOOP
    mov  [ebp - 56], eax                // char *key = gPtrKey



  ROUND_LOOP :
    mov   ecx, 0x0                     // Set ecx to 0 to calc indexes

    // EBX will store the offset for our starting points.
    // Ex. [0 + round * 4], etc...

  STARTING_POINTS :
    xor   eax, eax                      // Clear out eax
    mov   esi, [ebp - 8]                // esi = pHash
    mov    dx, 0x100                    // edx = 256
    movzx edx, dx

    mov   ebx, [ebp - 20]               // ebx = currRound
    shl   ebx, 0x2                      // ebx *= 4

    add   ebx, ecx
    inc   ecx                           // ecx += 1
    mov    al, [esi][ebx]               // eax = pHash[0 + round * 4]

    mul   edx                           // eax * 256

    mov   ebx, [ebp - 20]               // ebx = currRound
    shl   ebx, 0x2                      // ebx *= 4

    add   ebx, ecx                      // ebx += 1
    inc   ecx
    add    al, [esi][ebx]               // eax = pHash[1 + round * 4]
    //mov   esi, [ebp - 56]


  // Repeat the above code for idx1, idx2, hop1, hop2
  IDXS:
    cmp   ecx, 0x2
    je    IDX_1

    cmp   ecx, 0x6
    je    IDX_2

    jmp   HOP_OVERFLOW                  // The rest are hops. Ensure != 0

  HOPS :
    cmp   ecx, 0x4
    je    HOP_1

    cmp   ecx, 0x8
    je    HOP_2

  IDX_1 :
    mov[ebp - 32], eax                  // int idx1 = eax
    jmp   STARTING_POINTS

  HOP_1 :
    mov[ebp - 36], eax                  // int hop1 = eax
    jmp   STARTING_POINTS

  IDX_2 :
    mov[ebp - 24], eax                  // int idx2 = eax
    jmp   STARTING_POINTS

  HOP_2 :
    mov[ebp - 28], eax                  // int hop2 = eax
    jmp   FILE_SETUP

  HOP_OVERFLOW :
    cmp   ecx, 0                        // if hop == 0 then hop = 0xFFFF
    je    HOP_OVERFLOW_FIX
    jmp   HOP_OVERFLOW_RETN

  HOP_OVERFLOW_FIX :
    mov   ecx, 0xFFFF

  HOP_OVERFLOW_RETN :
    jmp   HOPS

  FILE_SETUP :
    mov   edi, [ebp - 16]               // edi = file
    mov   esi, [ebp - 56]               // esi = gptrKey

  FILE_LOOP :
    mov   edx, [ebp - 24]               // edx = idx2
    mov   ecx, [ebp - 40]               // ecx = x

    mov    al, [edi][ecx]               //  al = file[x]
    mov    bl, [esi][edx]               //  bl = key[idx2]
    xor    al, bl                       // file[x] ^ key[idx2]

    mov   ebx, [ebp - 28]               // ebx = hop2
    add   edx, ebx                      // idx2 + hop2
    cmp   edx, 0x10001                  // idx == 0x10001
    jbe   STORE_IDX1                    // skip if idx != 0x1001
    sub   edx, 0x10001

  STORE_IDX1:
    mov[ebp - 24], edx                  // idx2 = edx

    mov[ebp - 44], 0x01                 // count1
    mov[ebp - 48], 0x07                 // shifting count
    mov[ebp - 52], 0x80                 // count2

    // INSERT SWAP CODE HERE
    rol   al, 0x01                      // rotate left one bit

    // set up counts and push registers for use
    // for reversing bits
    push  ecx
    push  ebx
    mov   cl, [ebp - 48]                // Store shift count in cl
    mov   bl, 0x7F                      // bl = 127
    mov   ch, 0xFE                      // ch = 254

  REVERSE_BITS:
    mov   ah, al                        // Shift al to ah 
    and   ah, [ebp - 44]                // ah AND count1
    and   al, ch                        // al AND 254
    rol   ch, 1                         // ???
    shl   ah, cl                        // Move LSB to MSB
    mov   bh, ah                        // Store in bh
    mov   ah, al                        // ???
    and   ah, [ebp - 52]                // Restore count2 into ah
    and   al, bl                        // al AND bl
    ror   bl, 1                         // 
    shr   ah, cl
    or    bh, ah
    or    al, bh
    mov   ah, [ebp - 44]                // start manipulating counts
    shl   ah, 1
    mov  [ebp - 44], ah
    sub   cl, 2
    mov   ah, [ebp - 52]
    shr   ah, 1
    mov  [ebp - 52], ah
    cmp   ah, 0x10                      // if equal then do last iteration of loop
    jge   REVERSE_BITS
    pop   ebx
    pop   ecx

    // code to swap half nibbles
    mov   ah, al                        // store al in ah
    and   ah, 0x03                      // get first 2 bits
    shl   ah, 0x02                      // shift left 2 spaces
    mov   bh, al                        // store al in bh
    and   bh, 0x0C                      // get second 2 bits
    shr   bh, 0x02                      // shift right 2 spaces
    or    bh, ah                        // combine bits
    mov   ah, al                        // store al in ah
    mov   al, bh                        // move bh to al
    mov   bh, ah                        // store original al into bh
    and   ah, 0x30                      // get third 2 bits
    shl   ah, 0x02                      // shift left 2 spaces
    and   bh, 0xC0                      // get last 2 bits
    shr   bh, 0x02                      // shift right 2 spaces
    or    bh, ah                        // combine bits
    or    al, bh                        // combine everything back together

    ror   al, 0x05                      // rotate 1 bit to the right and swap nibbles
    // END OF SWAP CODE

    mov   edx, [ebp - 32]               // edx = idx1
    mov   ecx, [ebp - 40]               // ecx = x

    //mov    al, [edi][ecx]             //  al = file[x]
    mov    bl, [esi][edx]               //  bl = key[idx1]
    xor    al, bl                       // file[x] ^ key[idx1]
    mov   [edi][ecx], al                // Store al back into data

    mov   ebx, [ebp - 36]               // ebx = hop1
    add   edx, ebx                      // idx1 + hop1
    cmp   edx, 0x10001                  // idx == 0x10001
    jbe   STORE_IDX2                    // skip if idx != 0x1001
    sub   edx, 0x10001

  STORE_IDX2:
    mov  [ebp - 32], edx                // idx1 = edx

  FILE_LOOP_INC :
    mov   ecx, [ebp - 40]               // ecx =x
    inc   ecx                           // ecx++
    mov  [ebp - 40], ecx                // x = ecx

    cmp   ecx, [ebp - 12]               // x == len
    jnz   FILE_LOOP                     // Nope. Keep iterating
    je    ROUND_INC                     // Yes. Increase round


  ROUND_INC :
    mov   ecx, [ebp - 20]               // ecx = currRound
    dec   ecx                           // ecx--
    mov  [ebp - 20], ecx                // currRound = ecx

    cmp   ecx, -1                       // currRound == -1
    mov  [ebp - 40], 0x0                // Set x = 0 eagerly.
    jnz   ROUND_LOOP                    // currRound != -1. Keep looping.
    je    FINISH                        // currRound == -1. Finish.

  FINISH :
    add   esp, 0x38                     // Destroy locals

    pop   edx
    pop   ecx
    pop   ebx
    pop   eax
  }
 
EXIT_C_DECRYPT_DATA:
  return;
} // decryptData

// code to read in file and prepare for decryption
int decryptFile(FILE *fptrIn, FILE *fptrOut)
{
  char *buffer;
  unsigned int filesize;

  filesize = _filelength(_fileno(fptrIn));  // Linux???
  if(filesize > 0x1000000)          // 16 MB, file too large
  {
    fprintf(stderr, "Error - Input file too large.\n\n");
    return -1;
  }

  // use the password hash to encrypt
  buffer = (char *) malloc(filesize);
  if(buffer == NULL)
  {
    fprintf(stderr, "Error - Could not allocate %d bytes of memory on the heap.\n\n", filesize);
    return -1;
  }

  fread(buffer, 1, filesize, fptrIn); // read entire file
  decryptData(buffer, filesize);
  fwrite(buffer, 1, filesize, fptrOut);
  free(buffer);

  return 0;
} // decryptFile

//////////////////////////////////////////////////////////////////////////////////////////////////
FILE *openInputFile(char *filename)
{
  FILE *fptr;

  fptr = fopen(filename, "rb");
  if(fptr == NULL)
  {
    fprintf(stderr, "\n\nError - Could not open input file %s!\n\n", filename);
    exit(-1);
  }
  return fptr;
} // openInputFile

FILE *openOutputFile(char *filename)
{
  FILE *fptr;

  fptr = fopen(filename, "wb+");
  if(fptr == NULL)
  {
    fprintf(stderr, "\n\nError - Could not open output file %s!\n\n", filename);
    exit(-1);
  }
  return fptr;
} // openOutputFile


void usage(char *argv[])  //   cryptor.exe -e -i <input file> –k <keyfile> -p <password> [–r <#rounds>]
{
  printf("\n\nUsage:\n\n");
  printf("%s -<e=encrypt or d=decrypt> -i <message_filename> -k <keyfile> -p <password> [-r <#rounds>]\n\n", argv[0]);
  printf("-e        :encrypt the specified file\n");
  printf("-d        :decrypt the specified file\n");
  printf("-i filename   :the name of the file to encrypt or decrypt\n");
  printf("-p password   :the password to be used for encryption [default='password']\n");
  printf("-r <#rounds>  :number of encryption rounds (1 - 3)  [default = 1]\n");
  printf("-o filename   :name of the output file [default='encrypted.txt' or 'decrypted.txt'\n\n");
  exit(0);
} // usage

void parseCommandLine(int argc, char *argv[])
{
  int cnt;
  char ch;
  bool i_flag, o_flag, k_flag, p_flag, err_flag;

  i_flag = k_flag = false;        // these must be true in order to exit this function
  err_flag = p_flag = o_flag = false;   // these will generate different actions

  cnt = 1;  // skip program name
  while(cnt < argc)
  {
    ch = *argv[cnt];
    if(ch != '-')
    {
      fprintf(stderr, "All options must be preceeded by a dash '-'\n\n");
      usage(argv);
    }

    ch = *(argv[cnt]+1);
    if(0)
    {
    }

    else if(ch == 'e' || ch == 'E')
    {
      if(gOp != 0)
      {
        fprintf(stderr, "Error! Already specified encrypt or decrypt.\n\n");
        usage(argv);
      }
      gOp = 1;  // encrypt
    }

    else if(ch == 'd' || ch == 'D')
    {
      if(gOp != 0)
      {
        fprintf(stderr, "Error! Already specified encrypt or decrypt.\n\n");
        usage(argv);
      }
      gOp = 2;  // decrypt
    }

    else if(ch == 'i' || ch == 'I')
    {
      if(i_flag == true)
      {
        fprintf(stderr, "Error! Already specifed an input file.\n\n");
        usage(argv);
      }
      i_flag = true;
      cnt++;
      if(cnt >= argc)
      {
        fprintf(stderr, "Error! Must specify a filename after '-i'\n\n");
        usage(argv);
      }
      strncpy(gInFileName, argv[cnt], 256);
    }

    else if(ch == 'o' || ch == 'O')
    {
      if(o_flag == true)
      {
        fprintf(stderr, "Error! Already specifed an output file.\n\n");
        usage(argv);
      }
      o_flag = true;
      cnt++;
      if(cnt >= argc)
      {
        fprintf(stderr, "Error! Must specify a filename after '-o'\n\n");
        usage(argv);
      }
      strncpy(gOutFileName, argv[cnt], 256);
    }

    else if(ch == 'k' || ch == 'K')
    {
      if(k_flag == true)
      {
        fprintf(stderr, "Error! Already specifed a key file.\n\n");
        usage(argv);
      }
      k_flag = true;
      cnt++;
      if(cnt >= argc)
      {
        fprintf(stderr, "Error! Must specify a filename after '-k'\n\n");
        usage(argv);
      }
      strncpy(gKeyFileName, argv[cnt], 256);
    }

    else if(ch == 'p' || ch == 'P')
    {
      if(p_flag == true)
      {
        fprintf(stderr, "Error! Already specifed a password.\n\n");
        usage(argv);
      }
      p_flag = true;
      cnt++;
      if(cnt >= argc)
      {
        fprintf(stderr, "Error! Must enter a password after '-p'\n\n");
        usage(argv);
      }
      strncpy(gPassword, argv[cnt], 256);
    }

    else if(ch == 'r' || ch == 'R')
    {
      int x;

      cnt++;
      if(cnt >= argc)
      {
        fprintf(stderr, "Error! Must enter number between 1 and 3 after '-r'\n\n");
        usage(argv);
      }
      x = atoi(argv[cnt]);
      if(x < 1 || x > 3)
      {
        fprintf(stderr, "Warning! Entered bad value for number of rounds. Setting it to one.\n\n");
        x = 1;
      }
      gNumRounds = x;
    }

    else
    {
      fprintf(stderr, "Error! Illegal option in argument. %s\n\n", argv[cnt]);
      usage(argv);
    }

    cnt++;
  } // end while

  if(gOp == 0)
  {
    fprintf(stderr, "Error! Encrypt or Decrypt must be specified.\n\n)");
    err_flag = true;
  }

  if(i_flag == false)
  {
    fprintf(stderr, "Error! No input file specified.\n\n");
    err_flag = true;
  }

  if(k_flag == false)
  {
    fprintf(stderr, "Error! No key file specified.\n\n");
    err_flag = true;
  }

  if(p_flag == false)
  {
    fprintf(stderr, "Warning! Using default 'password'.\n\n");
  }

  if(o_flag == false && err_flag == false)  // no need to do this if we have errors
  {
    strcpy(gOutFileName, gInFileName);
    if(gOp == 1)  // encrypt
    {
      strcat(gOutFileName, ".enc");
    }
    if(gOp == 2)  // decrypt
    {
      strcat(gOutFileName, ".dec");
    }
  }

  if(err_flag)
  {
    usage(argv);
  }
  return;
} // parseCommandLine


void main(int argc, char *argv[])
{
#ifdef TEST_CODE
  char testData[] = "The big lazy brown FOX jumped 123 the 987 dog. Then he 8 a CHICKEN.";
  int numCAPS, numLow, numNonLetters;
  numCAPS = numLow = numNonLetters = 0;
  exCountLetters(testData, strlen(testData), &numCAPS, &numLow, &numNonLetters);
  printf("numCAPS=%d, numLow=%d, numNonLetters=%d\n", numCAPS, numLow, numNonLetters );
  exit(0);
#endif

  int length, resulti;

  // parse command line parameters
  parseCommandLine(argc, argv);   // sets global variables, checks input options for errors

  // open the input and output files
  gfptrIn = openInputFile(gInFileName);
  gfptrKey = openInputFile(gKeyFileName);
  gfptrOut = openOutputFile(gOutFileName);

  length = (size_t) strlen(gPassword);

  resulti = sha256(NULL, gPassword, length, gPasswordHash);   // get sha-256 hash of password
  if(resulti != 0)
  {
    fprintf(stderr, "Error! Password not hashed correctly.\n\n");
    exit(-1);
  }

  length = fread(gkey, 1, 65537, gfptrKey);
  if(length != 65537)
  {
    fprintf(stderr, "Error! Length of key file is not at least 65537.\n\n");
    exit(-1);
  }
  fclose(gfptrKey);
  gfptrKey = NULL;

  if(gOp == 1)  // encrypt
  {
    encryptFile(gfptrIn, gfptrOut);
  }
  else
  {
    decryptFile(gfptrIn, gfptrOut);
  }

  fclose(gfptrIn);
  fclose(gfptrOut);
  return;
} // main
