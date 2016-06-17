//
//  ViewController.m
//  AES256CTRDemo
//
//  Created by Thỏ on 6/16/16.
//  Copyright © 2016 Thỏ. All rights reserved.
//

#import "ViewController.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "NSData+Base64.h"
#import "aesctr.h"

@interface ViewController ()
// sBox is pre-computed multiplicative inverse in GF(2^8) used in subBytes and keyExpansion [§5.1.1]

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [self decryptAES];
    /*
    int r = 3, c = 4, i, j, count;
    
    int **arr = (int **)malloc(r * sizeof(int *));
    for (i=0; i<r; i++)
        arr[i] = (int *)malloc(c * sizeof(int));
    
    // Note that arr[i][j] is same as *(*(arr+i)+j)
    count = 0;
    for (i = 0; i <  r; i++)
        for (j = 0; j < c; j++)
            arr[i][j] = ++count;  // OR *(*(arr+i)+j) = ++count
    
    for (i = 0; i <  r; i++)
        for (j = 0; j < c; j++)
            printf("%d ", arr[i][j]);
    
    int k=0;
    while(arr[k] != nil)
        k++;
    
   
     int ary1[][5] = { {1, 2, 3, 4, 5},
     {6, 7, 8, 9, 0}
     };
     int ** ary = ary1;
     int rows =  sizeof ary / sizeof ary[0]; // 2 rows
     
     int cols = sizeof ary[0] / sizeof(int); // 5 cols
     
     char *a = "Le Minh Tu";
     int length = sizeof(a)/sizeof(char);//sizeof char is guaranteed 1, so sizeof(a) is enough
     int len2 = strlen(a);
     
    // Do any additional setup after loading the view, typically from a nib.
    //[self decryptAES];
    NSString *password = @"1234567890ABCDEFGHIJKLMNOPQRSTUV";
    //NSString *plaintext = @"Steve Job";
    NSString *cipherText = @"hQJPaJkwYlfd10iOS+I3MRs=";
    
    // uint8_t *cipher = (uint8_t *)"Oh0bWÝ×HKâ71";//cipherText.UTF8String;
    // uint8_t *pass = (uint8_t *)password.UTF8String;
    char* cipher = "Oh0bWÝ×HKâ71";//cipherText.UTF8String;

    char* pass = "1234567890ABCDEFGHIJKLMNOPQRSTUV";//(char *)password.UTF8String;
    
    printf("cipher: %s",cipher);
    
  //  char* test = "abcdef";
  //  int lenCipher  =sizeof(test) / sizeof(char*); //should give 3
  //  int len = strlen(test);
  //  int len1 = sizeof(test) / sizeof(test[0]);

    
  // char *result = decryptAES(cipher, pass, 256);
    
  //  NSString *s = [NSString stringWithUTF8String:(char *)result];
    
  //  NSLog(@"Plaintext: %@", s);
    */
   // [self testDecrypt];
}

-(void)decryptAES{
    char* password = "1234567890ABCDEFGHIJKLMNOPQRSTUV";
    NSString *cipherText1 = @"NgCSCfWYY1fD4VA3r0Y+THYb+HXd1XPpga7b4Zh8QCRMYE2KXrBrfI9ee+amU88z+nyqiDji4mlLskLH9ETLcvfjAu5xQxcVn+FiE0R0UjwxoLeP32skWaFiYET9B1FK8vm3Ncvrn3RjWhS183sGhWjCubO3ECEQEmKKOUgZS50zFV0kGa5hNWZ7qa1U/RI/QJGRQqwxUhkfAxgvzo3qkBIiBREcD2Q5h3DYTadm76kkA+xB9XrYPz2mMCQL39UPSm4yYX6KJmAPG6kLNg6F90Npb5jGEeHqizkOLTwq3cw+CMV52SCLgBsVDg3QsjE3My04V4NU0pP2K4+xRpLtnysKIZCyEsWg5yf/dJxbWYsRfIJjC/JUGwcQ+O14ZKQVKoicukFR4qcfI8p7cpk4Cv2Fhb9bHL0SY8HjdMq+f9AbF/aYVaykJSPFE5X8kocP7sxOytbhRXx2dF1u1xvRtzT9QPytqQksH4BeheuhGpWZa1z6FPya35/cfVvEuI6Z/0kiJ4fD/DdJB5QJtdQi0JPnvdmBm1PcQfzsRy1eKgc08+UA4dPd+uskjmBHGaYtrBsSdWL13HMnShZHXoPscnln/ZMkHN6EcXyUvttc866+sTMR9V48A+l65X1S7l5vFB5rTRsfq7BbOlLYE3HmDbSv5sebR+tDXN6i66EzMh5R5CSEqTd4kuzQzOROZcwH1DaJ1uuGR4/+S2wiPRAk6LZRfH0wL+6r3NHNw49Dxr5PpMgd2FwK2kC5D+ei/u0mhQric23/ZrmwEdY3UoCu63vrsxM/oOQjcdpH2y7NdLDyhr7JFiNqWck+wLxPLqWGwqjCpb5LX0Nt49tX6tOuTM2+6/k2sWeyF9ojLxicmt0jbhUyXP6AvQlo7jiPsAeyQgX4lldKl/MZakhJAPRfA4Z7KialQvGRDPFpqktO2bZOBh5XiNbi0P3iJnKmU2MNSLM3z8dJ86thH95yldSWRKOY2j5K8aXHt5J+HsEDtqkbbix8VU0AC/ERsn++VMhUDWfCia+SVrm4ozj7ahA3i60x8LX6x12ZRsC2GlzpNc/vyJAhwycjtqA7Wa0DGtlTIxe+3AFe6JUPLSdtBjs65qjB0niQxgegWLsed9npx9YQZ/4vb4SaeX0gXN7A9DEjBoAueBeO1rYwneGmEo8DRGHYOe2sve/1db6kf4n1E0s0eg2nJyCjngdZiXzJkQN/lkRVUAm+IHByV54DzNQm5FNqRCrViuFo99hhY0vS0xWHhfxuFskYt2FBan8Hm+Va8hfmYYjaXnxnoSqXoawgwjVlsb8+71ucOT5QxoEp9CxoULdwfVB3o0Ait0JYlnSMEdSheOMRLlAJEG9lOIPIik8xBmB4zItdbQ3+s9fRAF/LV4TIU6wBP8WeATR/N+fbHILKjvwix0/SkeuNLdFMyfDmBfBfOeDGBDx/HpmbwFCt35k+rwf4EdGNZ/xp1tMUX8rJbXJosUSQEPzolrzrFa4kgSBdbketyqNLIH4kBIqZ0bNABmAeUfTGICnnHLTJWlnQS7RFG1z5ECGY1/KkKpDudIYP4gVIOooMgfGwk0Jm9bLjaI7VLU5VyfHs49JskLvV9hdMlXn0AAr+eu4L8NILMBWPnw==";//@"hQJPaJkwYlfd10iOS+I3MRs=";
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:cipherText1 options:0];
    NSString *ciphertext = [[NSString alloc] initWithData:decodedData encoding:NSISOLatin1StringEncoding];
    
   char* cipher = [[ciphertext description] UTF8String];
    char* result;
    decryptAES(result,cipher, password );
   // Decrypt([ciphertext UTF8String], password);
    
}



@end
