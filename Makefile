CXX	      := g++
CXXFLAGS  := -p -g -std=c++11  -Weffc++
OBJDIR	  := build
LDFLAGS   := -fPIC

HAVE_EXANIC_H := ${shell $(CXX) $(CXXFLAGS) -include exanic/exanic.h -E -x c /dev/null >/dev/null 2>&1 && echo 1 || echo 0}
ifeq ($(HAVE_EXANIC_H),1)
  CPPFLAGS += -DWITH_EXANIC
  LDLIBS += -lexanic
endif

FILES_CPP := $(wildcard *.cpp)
FILES_OBJ := $(FILES_CPP:%.cpp=$(OBJDIR)/%.o)

$(OBJDIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -MMD -c -o $@ $<

.PHONY: all clean print-config

all: print-config timestamp-decoder

print-config:
ifneq ($(HAVE_EXANIC_H),1)
	@echo 'NOTE: Building without support for direct ExaNIC capture (could not find <exanic/exanic.h>)'
endif

clean:
	rm -rf $(OBJDIR)

# file dependencies
-include $(FILES_OBJ:.o=.d)

timestamp-decoder: $(OBJDIR)/exe/timestamp-decoder.o $(FILES_OBJ)
	@mkdir -p $(@D)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $(OBJDIR)/$@


