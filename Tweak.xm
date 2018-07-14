#include <string.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <pthread.h>

#define BUF_SIZE 2048

#define DLog(x, ...) NSLog(@"*****"x, __VA_ARGS__)

void showAlert(NSString *title, NSString *message){
	UIAlertController *a = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];

	UIAlertAction *ok = [UIAlertAction actionWithTitle:@"Okay & Exit" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){
		exit(0);
	}];
	[a addAction:ok];

	[[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:a animated:false completion:nil];    
}

void copyFile(const char *from, const char *to){
	FILE *src = fopen(from, "rb");
	if(!src){
	   showAlert(@"Error", @"copyFile: couldn't open src");
	   return;
	}

	// find size of this file
	fseek(src, 0, SEEK_END);
	int fileSize = ftell(src);
	rewind(src);

	DLog("fileSize %d", fileSize);

	char *srcBuffer = (char *)malloc(fileSize);

	size_t read = fread(srcBuffer, sizeof(char), fileSize, src);

	DLog("fread read %d bytes", read);

	fclose(src);

	FILE *dst = fopen(to, "wb");

	if(!dst){
	   showAlert(@"Error", @"copyFile: couldn't open dst");
	   return;
	}

	size_t wrote = fwrite(srcBuffer, sizeof(char), fileSize, dst);

	DLog("fwrite wrote %d bytes", wrote);

	fclose(dst);
	free(srcBuffer);

	NSLog(@"*****copyFile: done!");
}

void *doDecrypt(void *arg){
	uint64_t aslrSlide = _dyld_get_image_vmaddr_slide(0);

	// get the target's mach_header
	struct mach_header_64 *mach_header = (struct mach_header_64 *)malloc(sizeof(struct mach_header_64));
	vm_size_t size = sizeof(struct mach_header_64);

	kern_return_t err = vm_read_overwrite(mach_task_self(), (vm_address_t)(aslrSlide + 0x100000000), size, (pointer_t)mach_header, &size);

	if(err){
		showAlert(@"Error", @"Couldn't read mach_header");

		pthread_exit(NULL);
	}

	DLog("ASLR: %llx", aslrSlide);
	DLog("mach_header->magic %x, mach_header->sizeofcmds %x", mach_header->magic, mach_header->sizeofcmds);

	if(mach_header->magic != MH_MAGIC_64){
		showAlert(@"Error", @"mach_header->magic != feedfacf");

		pthread_exit(NULL);
	}

	free(mach_header);

	// go through the load commands to find the __TEXT segment command
	struct segment_command_64 *__TEXT = NULL;
	struct load_command *command = (struct load_command *)malloc(sizeof(struct load_command));

	vm_address_t currentAddress = aslrSlide + 0x100000000 + sizeof(struct mach_header_64);
	vm_size_t segmentSize = sizeof(struct load_command);

	vm_read_overwrite(mach_task_self(), currentAddress, segmentSize, (pointer_t)command, &segmentSize);

	// TODO: would this ever be an infinite loop? we already checked for feedfacf
	while(strcmp(((struct segment_command_64 *)command)->segname, "__TEXT") != 0){
		command = (struct load_command *)((uint8_t *)currentAddress + command->cmdsize);
	}

	__TEXT = (struct segment_command_64 *)malloc(sizeof(struct segment_command_64));
	memcpy(__TEXT, (const void *)command, sizeof(struct segment_command_64));

	DLog("found text! start: %llx, end: %llx", __TEXT->vmaddr, __TEXT->vmaddr + __TEXT->vmsize);

	// read __TEXT segment
	vm_size_t bytesLeftToRead = __TEXT->vmsize;
	vm_size_t bytesRead = 0;
	vm_address_t current = __TEXT->vmaddr + aslrSlide;
	vm_address_t end = __TEXT->vmaddr + __TEXT->vmsize + aslrSlide;

	unsigned char *textBuffer = (unsigned char *)malloc(bytesLeftToRead);

	while(current < end){
		vm_size_t chunk = 0x100000;

		if(chunk > bytesLeftToRead)
			chunk = bytesLeftToRead;

		vm_read_overwrite(mach_task_self(), current, chunk, (vm_address_t)&textBuffer[bytesRead], &chunk);

		bytesRead += chunk;
		current += chunk;
		bytesLeftToRead -= chunk;

		DLog("%llx / %llx: reading __TEXT... %.2f%%", current-aslrSlide, __TEXT->vmaddr + __TEXT->vmsize, ((float)bytesRead/__TEXT->vmsize)*100);
	}

	const char *executablePath = [[[NSBundle mainBundle] bundlePath] UTF8String];
	const char *executableName = getprogname();

	char *pathToTarget = (char *)malloc(BUF_SIZE);
	strcpy(pathToTarget, executablePath);
	strcat(pathToTarget, "/");
	strcat(pathToTarget, executableName);

	DLog("pathToTarget %s", pathToTarget);

	char *pathToDecryptedTarget = (char *)malloc(BUF_SIZE);
	strcpy(pathToDecryptedTarget, [NSHomeDirectory() UTF8String]);
	strcat(pathToDecryptedTarget, "/Documents/");
	strcat(pathToDecryptedTarget, executableName);
	strcat(pathToDecryptedTarget, " decrypted");

	NSLog(@"*****copying file...");

	copyFile(pathToTarget, pathToDecryptedTarget);

	NSLog(@"*****done!");

	FILE *decryptedTargetPtr = fopen(pathToDecryptedTarget, "r+b");

	if(!decryptedTargetPtr){
		showAlert(@"Error", @"Couldn't open decrypted target for writing");
		pthread_exit(NULL);
	}

	uint64_t curFileOffset = 0x0;
	long int amountToWrite = 0x100000;
	uint64_t textEnd = __TEXT->vmsize;

	while(amountToWrite != 0 && curFileOffset < textEnd){
	   if(textEnd - curFileOffset < amountToWrite)
		   amountToWrite = textEnd - curFileOffset;

	   fwrite(&textBuffer[curFileOffset], amountToWrite, sizeof(char), decryptedTargetPtr);

	   curFileOffset += amountToWrite;

	   DLog("%llx / %llx: writing to __TEXT... %.2f%%", curFileOffset, textEnd, ((float)curFileOffset/textEnd)*100);
	}

	NSLog(@"*****we're done with this part");

	free(__TEXT);
	free(textBuffer);
	free(pathToTarget);

	showAlert(@"Done!", [NSString stringWithFormat:@"Find your executable at %@", [NSString stringWithUTF8String:pathToDecryptedTarget]]);

	free(pathToDecryptedTarget);

	pthread_exit(NULL);
}

__attribute__ ((constructor)) static void decrypt() {
	pthread_t decryptionThread;
	pthread_create(&decryptionThread, NULL, doDecrypt, NULL);
}
