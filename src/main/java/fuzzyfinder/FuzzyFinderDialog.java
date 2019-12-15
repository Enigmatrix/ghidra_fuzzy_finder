package fuzzyfinder;

import com.jeta.forms.components.separator.TitledSeparator;
import docking.DialogComponentProvider;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import me.xdrop.fuzzywuzzy.FuzzySearch;
import me.xdrop.fuzzywuzzy.model.BoundExtractedResult;
import org.python.bouncycastle.util.io.Streams;
import org.w3c.dom.Text;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class FuzzyFinderDialog extends DialogComponentProvider {

    private FuzzyFinderPlugin plugin;
    private JScrollPane resultsPane;
    private JTextArea resultsText;

    public FuzzyFinderDialog(FuzzyFinderPlugin plugin) {
        super(Info.NAME);
        this.plugin = plugin;

        addWorkPanel(buildMainPanel());
        addOKButton();
        addCancelButton();
        setMinimumSize(getPreferredSize());
    }

    public JPanel buildMainPanel() {
        var inner = new JPanel();
        inner.setPreferredSize(new Dimension(500, 800));

        var searchText = new JTextField();
        searchText.setToolTipText("Search ...");
        searchText.setFont(searchText.getFont().deriveFont(18.0f));
        searchText
            .getDocument()
            .addDocumentListener(new TextChangedListener(() -> {
                search(searchText.getText());
            }
        ));
        inner.add(searchText);

        resultsText = new JTextArea(30, 30);
        resultsPane = new JScrollPane(resultsText);
        inner.add(resultsPane);

        return inner;
    }

    public void search(String text) {
        var programs = Arrays.stream(plugin.getOpenedPrograms())
                .flatMap(x -> Stream.concat(
                        asStream(x.getFunctionManager().getFunctions(true)).map(SearchResult::new),
                        asStream(x.getSymbolTable().getAllSymbols(true)).map(SearchResult::new)));

        var results = FuzzySearch.extractTop(text, programs.collect(Collectors.toList()), SearchResult::toString, 10);
        renderSearchResults(results);
    }

    public void renderSearchResults(List<BoundExtractedResult<SearchResult>> results) {
        resultsText.setText("");
        for(var result : results) {
            resultsText.append(result.getReferent().getName() + "\n");
        }
    }

    public void show() {

        plugin.getTool().showDialog(this);
    }

    private static <T> Stream<T> asStream(Iterator<T> sourceIterator) {
        return asStream(sourceIterator, false);
    }

    private static <T> Stream<T> asStream(Iterator<T> sourceIterator, boolean parallel) {
        Iterable<T> iterable = () -> sourceIterator;
        return StreamSupport.stream(iterable.spliterator(), parallel);
    }

    private class TextChangedListener implements DocumentListener {

        private Runnable runnable;

        public TextChangedListener(Runnable runnable) {
            this.runnable = runnable;
        }

        @Override
        public void insertUpdate(DocumentEvent e) {
            runnable.run();
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            runnable.run();
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            runnable.run();
        }
    }
}
