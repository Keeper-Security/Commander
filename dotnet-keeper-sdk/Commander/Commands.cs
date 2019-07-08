using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;
using KeeperSecurity.Sdk;

namespace Commander
{
    public interface ICommand
    {
        int Order { get; }
        string Description { get; }
        Task ExecuteCommand(string args);
    }

    public class SimpleCommand : ICommand
    {
        public int Order { get; set; }
        public string Description { get; set; }
        public Func<string, Task> Action { get; set; }

        public async Task ExecuteCommand(string args)
        {
            if (Action != null)
            {
                await Action(args);
            }
        }
    }

    public static class CommandExtensions
    {
        public static bool IsWhiteSpace(char ch)
        {
            return char.IsWhiteSpace(ch);
        }
        public static bool IsPathDelimiter(char ch)
        {
            return ch == '/';
        }
        public static IEnumerable<string> TokenizeArguments(this string args)
        {
            return TokenizeArguments(args, IsWhiteSpace);
        }
        public static IEnumerable<string> TokenizeArguments(this string args, Func<char, bool> isDelimiter)
        {
            var sb = new StringBuilder();
            int pos = 0;
            bool isQuote = false;
            bool isEscape = false;
            while (pos < args.Length)
            {
                char ch = args[pos];

                if (isEscape)
                {
                    isEscape = false;
                    sb.Append(ch);
                }
                else
                {
                    if (ch == '\\')
                    {
                        isEscape = true;
                    }
                    else if (ch == '"')
                    {
                        isQuote = !isQuote;
                    }
                    else if (!isQuote && isDelimiter(ch))
                    {
                        if (sb.Length > 0)
                        {
                            yield return sb.ToString();
                            sb.Length = 0;
                        }
                    }
                    else
                    {
                        sb.Append(ch);
                    }
                }
                pos++;
            }
            if (sb.Length > 0)
            {
                yield return sb.ToString();
            }
        }
    }

    public class ParsableCommand<T> : ICommand where T : class
    {

        public int Order { get; internal set; }
        public string Description { get; set; }
        public Func<T, Task> Action { get; internal set; }

        public async Task ExecuteCommand(string args)
        {
            var res = Parser.Default.ParseArguments<T>(args.TokenizeArguments());
            T options = null;
            res
            .WithParsed(o =>
            {
                options = o;
            });
            if (options != null)
            {
                await Action(options);
            }
        }
    }

    public abstract class CliCommands
    {
        public CliCommands()
        {
            Commands.Add("clear", new SimpleCommand
            {
                Order = 1000,
                Description = "Clear the screen",
                Action = (args) =>
                {
                    Console.Clear();
                    return Task.FromResult(true);
                }
            });

            Commands.Add("quit", new SimpleCommand
            {
                Order = 1001,
                Description = "Quit",
                Action = (args) =>
                {
                    Finished = true;
                    NewCommands = null;
                    return Task.FromResult(true);
                }
            });
            CommandAliases.Add("c", "clear");
            CommandAliases.Add("q", "quit");
        }
        public abstract string GetPrompt();
        public CliCommands NewCommands { get; protected set; }
        public bool Finished { get; protected set; }
        public IDictionary<string, ICommand> Commands { get; } = new Dictionary<string, ICommand>();
        public IDictionary<string, string> CommandAliases { get; } = new Dictionary<string, string>();
        public Queue<string> CommandQueue { get; }  = new Queue<string>();
    }

    public class NotConnectedCliCommands : CliCommands
    {
        private readonly AuthContext _auth;

        private class LoginOptions : IUserCredentials {
            [Option("password", Required = false, HelpText = "master password")]
            public string Password { get; set; }

            [Value(0, Required = true, MetaName="email", HelpText = "account email")]
            public string Username { get; set; }
        }

        public NotConnectedCliCommands(AuthContext auth) : base()
        {
            _auth = auth;

            Commands.Add("login", new ParsableCommand<LoginOptions>
            {
                Order = 10,
                Description = "Login to Keeper",
                Action = DoLogin
            });

            Commands.Add("server", new SimpleCommand {
                Order = 20,
                Description = "Display or change Keeper Server",
                Action = (args) => {
                    if (!string.IsNullOrEmpty(args))
                    {
                        _auth.Api.Server = args.AdjustServerUrl();
                    }
                    Console.WriteLine(string.Format("Keeper Server: {0}", _auth.Api.Server.AdjustServerUrl()));
                    return Task.FromResult(true);
                }
            });

        }

        private async Task DoLogin(LoginOptions options)
        {
            await _auth.Login(new UserConfiguration(options));
            if (!string.IsNullOrEmpty(_auth.SessionToken)) {
                Finished = true;
                var vault = new Vault(_auth);
                var connectedCommands = new ConnectedCommands(vault);
                connectedCommands.ScheduleSyncDown();
                NewCommands = connectedCommands;
            }
        }

        public override string GetPrompt()
        {
            return "Not logged in";
        }
    }
}
