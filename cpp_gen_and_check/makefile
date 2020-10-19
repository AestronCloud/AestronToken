
# output path
BIN = .

TLIB = libtoken.a 

# debug stuff 
ifeq ($(CFLAG), DEBUG)
CFLAGS += -std=c++11 
endif

AR  = ar -cqs
# itermidiate objects
OBJ = tokenCheck.o token.o urlEncrypt.o 


# include file path
#INC = -I. 
INCLUDE = -I../ -I../../  -I../../..

TARGETS = $(BIN)/$(TLIB)
 
all : $(TARGETS)
	cp $(TARGETS) ../

$(BIN)/$(TLIB) : $(OBJ)
	$(AR) $@ $(OBJ) 


token_d : $(OBJ) $(BIN)/libtoken.a example.o
	g++ -g -o $@ ./libtoken.a -lpthread -lcrypto example.o
	
%.o : %.c
	gcc -g $(INCLUDE) $(CFLAGS) -c $< -o $@

%.o : %.cpp
	g++ -g  $(INCLUDE) $(CFLAGS) -c $< -o $@


example.o : example.cpp
        g++ -g -std=c++11 $(INCLUDE) $(CFLAGS) -c $< -o $@

# prepare the bin dir	
.PHONY : prepare	
prepare : 
		-mkdir $(BIN)
	  
.PHONY : clean
clean  :
		-rm -rf $(BIN)/$(TLIB) $(OBJ) ../$(TLIB) $(TARGETS)
