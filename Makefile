CXX	      := g++
CXXFLAGS  := -p -g -std=c++11  -Weffc++
OBJDIR	  := build
LDFLAGS   := -fPIC
LDLIBS    := -lexanic

FILES_CPP := $(wildcard *.cpp)
FILES_OBJ := $(FILES_CPP:%.cpp=$(OBJDIR)/%.o)

$(OBJDIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -MMD -c -o $@ $<

.PHONY: all

all: capture-hw-time 

.PHONY: clean
clean:
	rm -rf $(OBJDIR)

# file dependencies
-include $(FILES_OBJ:.o=.d)

capture-hw-time: $(OBJDIR)/exe/capture-hw-time.o $(FILES_OBJ)
	@mkdir -p $(@D)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $(OBJDIR)/$@


