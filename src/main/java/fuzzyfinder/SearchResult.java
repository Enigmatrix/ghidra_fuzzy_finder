package fuzzyfinder;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;

public class SearchResult {
    private String name;
    private String desc;
    private Address addr;
    private ResultType type;

    public SearchResult(Function func) {
        this.name = func.getName();
        this.desc = func.getPrototypeString(true, true);
        this.addr = func.getEntryPoint();
        this.type = ResultType.Function;
    }

    public SearchResult(Symbol symbol) {
        this.name = symbol.getName(false);
        this.desc = symbol.getName(true);
        this.addr = symbol.getAddress();
        this.type = ResultType.Symbol;
    }

    public String getName() {
        return name;
    }

    public Address getAddr() {
        return addr;
    }

    public ResultType getType() {
        return type;
    }

    public String getDesc() {
        return desc;
    }

    @Override
    public String toString() {
        return getName() + " " + getDesc();
    }
}

