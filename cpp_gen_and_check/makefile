
# output path
BIN = .

TLIB = libtoken.a 

CFLAGS += -std=c++11 

AR  = ar -cqs
# itermidiate objects
OBJ = tokenCheck.o token.o urlEncrypt.o 

INCLUDE = -I.

TARGETS = $(BIN)/$(TLIB) example.o token_d
 
all : $(TARGETS)

$(BIN)/$(TLIB) : $(OBJ)
	$(AR) $@ $(OBJ) 


token_d : $(OBJ) $(BIN)/libtoken.a example.o
	g++ -g $(CFLAGS) $(INCLUDE) -o $@ example.o ./libtoken.a -lpthread -lcrypto -lz
	
%.o : %.c
	gcc -g $(INCLUDE) $(CFLAGS) -c $< -o $@

%.o : %.cpp
	g++ -g $(INCLUDE) $(CFLAGS) -c $< -o $@


example.o : example.cpp
	g++ -g $(INCLUDE) $(CFLAGS) -c $< -o $@

.PHONY : prepare	
prepare : 
		-mkdir $(BIN)
	  
.PHONY : clean
clean  :
		-rm -rf $(BIN)/$(TLIB) $(OBJ) ../$(TLIB) $(TARGETS)
