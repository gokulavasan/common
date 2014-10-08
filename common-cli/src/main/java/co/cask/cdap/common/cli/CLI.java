/*
 * Copyright © 2012-2014 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package co.cask.cdap.common.cli;

import co.cask.cdap.common.cli.completers.DefaultStringsCompleter;
import co.cask.cdap.common.cli.completers.PrefixCompleter;
import co.cask.cdap.common.cli.internal.TreeNode;
import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import jline.console.ConsoleReader;
import jline.console.UserInterruptException;
import jline.console.completer.AggregateCompleter;
import jline.console.completer.Completer;

import java.io.IOException;
import java.io.PrintStream;
import java.util.List;
import java.util.Map;

/**
 * <p>
 * Provides a command-line interface (CLI) with auto-completion,
 * interactive and non-interactive modes, and other typical shell features.
 * </p>
 *
 * <p>
 * {@link #commands} contains all of the available commands, and {@link #completers}
 * contains the available completers per argument type. For example, if we have a command
 * with the pattern "start flow <flow-id>" and a completer keyed by "flow-id" in the {@link #completers} map,
 * then when the user enters "start flow" and then hits TAB, the completer will be activated to provide
 * auto-completion.
 * </p>
 *
 * @param <T> type of {@link Command} that this {@link CLI} will use
 */
public class CLI<T extends Command> {

  private final CommandSet<T> commands;
  private final CompleterSet completers;
  private final ConsoleReader reader;

  /**
   * @param commands the commands to use
   * @param completers the completers to use
   * @throws IOException if unable to construct the {@link ConsoleReader}.
   */
  public CLI(Iterable<T> commands, Map<String, Completer> completers) throws IOException {
    this.commands = new CommandSet<T>(commands);
    this.completers = new CompleterSet(completers);
    this.reader = new ConsoleReader();
    this.reader.setPrompt("cli> ");
  }

  /**
   * Starts the CLI given command-line arguments.
   *
   * If no arguments are given, the CLI is started in interactive mode
   * (e.g. user may enter in multiple commands). If arguments are given,
   * the arguments are treated as a command, and the CLI executes the single
   * command that is given.
   *
   * @param args the arguments
   * @param output the {@link PrintStream} to write messages to
   * @throws IOException if there's an issue in reading the input
   */
  public void run(String[] args, PrintStream output) throws IOException {
    if (args.length == 0) {
      startInteractiveMode(output);
    } else {
      execute(Joiner.on(" ").join(args), output);
    }
  }

  /**
   * @return the {@link ConsoleReader} that is being used to read input.
   */
  public ConsoleReader getReader() {
    return reader;
  }

  /**
   * Executes a command given some input.
   *
   * @param input the input
   * @param output the {@link PrintStream} to write messages to
   */
  public void execute(String input, PrintStream output) {
    CommandMatch match = commands.findMatch(input);
    try {
      match.getCommand().execute(match.getArguments(), output);
    } catch (Exception e) {
      output.println("Error: " + e.getMessage());
    }
  }

  /**
   * Starts interactive mode, which provides a shell to enter multiple commands and use auto-completion.
   *
   * @param output {@link java.io.PrintStream} to write to
   * @throws java.io.IOException if there's an issue in reading the input
   */
  public void startInteractiveMode(PrintStream output) throws IOException {
    this.reader.setHandleUserInterrupt(true);

    List<Completer> completerList = generateCompleters();
    for (Completer completer : completerList) {
      reader.addCompleter(completer);
    }

    while (true) {
      String line;

      try {
        line = reader.readLine();
      } catch (UserInterruptException e) {
        continue;
      }

      if (line == null) {
        output.println();
        break;
      }

      if (line.length() > 0) {
        String command = line.trim();
        try {
          execute(command, output);
        } catch (Exception e) {
          output.println("Error: " + e.getMessage());
        }
        output.println();
      }
    }
  }

  private List<Completer> generateCompleters() {
    TreeNode<String> commandTokenTree = new TreeNode<String>();

    for (Command command : commands) {
      String pattern = command.getPattern();
      String[] tokens = pattern.split(" ");

      TreeNode<String> currentNode = commandTokenTree;
      for (String token : tokens) {
        currentNode = currentNode.findOrCreateChild(token);
      }
    }

    return generateCompleters(null, commandTokenTree);
  }

  private List<Completer> generateCompleters(String prefix, TreeNode<String> commandTokenTree) {
    List<Completer> completers = Lists.newArrayList();
    String name = commandTokenTree.getData();
    String childPrefix = (prefix == null || prefix.isEmpty() ? "" : prefix + " ") + (name == null ? "" : name);

    if (!commandTokenTree.getChildren().isEmpty()) {
      List<String> nonArgumentTokens = Lists.newArrayList();
      List<String> argumentTokens = Lists.newArrayList();
      for (TreeNode<String> child : commandTokenTree.getChildren()) {
        String childToken = child.getData();
        if (childToken.matches("<\\S+>")) {
          argumentTokens.add(childToken);
        } else {
          nonArgumentTokens.add(child.getData());
        }
      }

      for (String argumentToken : argumentTokens) {
        // chop off the < and > or [ and ]
        String completerType = argumentToken.substring(1, argumentToken.length() - 1);
        Completer argumentCompleter = getCompleterForType(completerType);
        if (argumentCompleter != null) {
          completers.add(prefixCompleterIfNeeded(childPrefix, argumentCompleter));
        }
      }

      completers.add(prefixCompleterIfNeeded(childPrefix, new DefaultStringsCompleter(nonArgumentTokens)));

      for (TreeNode<String> child : commandTokenTree.getChildren()) {
        completers.addAll(generateCompleters(childPrefix, child));
      }
    }

    return Lists.<Completer>newArrayList(new AggregateCompleter(completers));
  }

  private Completer prefixCompleterIfNeeded(String prefix, Completer completer) {
    if (prefix != null && !prefix.isEmpty()) {
      return new PrefixCompleter(prefix.replaceAll("<\\S+>", "{}"), completer);
    } else {
      return completer;
    }
  }

  private Completer getCompleterForType(String completerType) {
    return completers.getCompleter(completerType);
  }

}