CC = g++
OBJS =  main.o bProtocol.o bProfile.o sdpscan.o prtL2CAP.o prtRFCOMM.o prtOBEX.o \
	iGenerator.o devscan.o strategy.o pairing.o global.o Fuzzer.o prtSDP.o \
	Database.o packet.o
TARGET = BTTestingTool

.SUFFIXES : .c .o

all : $(TARGET)

$(TARGET): $(OBJS)
	     $(CC) -o $@ $(OBJS) -lbluetooth -lsqlite3

clean :
	rm -f $(OBJS) $(TARGET)
