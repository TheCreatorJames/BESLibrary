using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BasylEncryptionStandard
{
    /// <summary>
    /// This allows you to pass in a string that will be treated as the seed string function.
    /// Two possible variables are "seed" and "pos". You may also use literal values like "10". 
    /// 
    /// Examples of things that can be passed in: 
    /// 10 + 20 + 30 * pos + seed * pos
    /// 10 * pos * seed
    /// etc.
    /// </summary>
    public class SeedFunctionStringAdaptor : BasylPseudoAdaptor
    {
        private string function;
        public SeedFunctionStringAdaptor(string function)
        {
            this.function = function;
        }

        /// <summary>
        /// Gets the function.
        /// </summary>
        /// <returns></returns>
        public String GetFunction()
        {
            return function;
        }

        /// <summary>
        /// Sets the function.
        /// </summary>
        /// <param name="function"></param>
        public void SetFunction(string function)
        {
            this.function = function;
        }

        private static Dictionary<String, Int32> operators;
        /// <summary>
        /// Converts infix input to reverse polish notation.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static String ConvertToRPN(string input)
        {
            string result = "";
            if (operators == null)
            {
                //add the operators and their priorities.
                operators = new Dictionary<string, int>();

                operators.Add("|", 5);
                operators.Add("&", 5);

                operators.Add("^", 4);

                operators.Add("*", 3);
                operators.Add("/", 3);
                operators.Add("%", 3);

                operators.Add("+", 2);
                operators.Add("-", 2);
            }

            //provide spacing in between operators and possible literals/variables.
            foreach (String ops in operators.Keys)
            {
                input = input.Replace(ops, " " + ops + " ");
            }

            //same as the operators, but parenthesis.
            input = input.Replace("(", " ( ");
            input = input.Replace(")", " ) ");
     

            Queue<String> operands = new Queue<string>();
            Queue<String> replacements = new Queue<string>();
            Stack<String> operats = new Stack<string>();

            //find and parse everything in parenthesis.
            while (input.IndexOf("(") != -1)
            {
                int pos = input.IndexOf("(");
                int pos2 = input.IndexOf(")", pos + 1);


                int tpos = pos;
                while (input.IndexOf("(", tpos + 1) < pos2 && input.IndexOf("(", tpos + 1) != -1)
                {
                    pos2 = input.IndexOf(")", pos2 + 1);
                    tpos = input.IndexOf("(", tpos + 1);
                }


                // String rp = input.Substring(pos, pos2 + 1 - pos);
                replacements.Enqueue(ConvertToRPN(input.Substring(pos + 1, pos2 - pos - 1)));
                input = input.Substring(0, pos) + "_#R#_" + input.Substring(pos2 + 1);
            }


            String[] tokens = input.Split(' ');

            int level = -10;
            //parses through all of the tokens.
            foreach (String tok in tokens)
            {
                if (tok.Length == 0)
                { }
                else
                if (operators.ContainsKey(tok))
                {
                    if (level >= operators[tok] && (operats.Count > 0 && operats.Peek() != tok))
                    {

                        while (operands.Count != 0)
                        {
                            result += operands.Dequeue() + " ";
                        }
                        
                        while (operats.Count != 0 && operators[operats.Peek()] >= operators[tok])
                        {
                            result += operats.Pop() + " ";
                        }

                    }

                    operats.Push(tok);
                    level = operators[(tok)];
                }
                else if (tok.Equals("_#R#_"))
                {
                    //push something like a variable?
                    if (replacements.Count != 0)
                        operands.Enqueue(replacements.Dequeue());
                    else operands.Enqueue(tok);
                }

                else if (tok.Equals(";"))
                {
                    //force flush
                    while (operands.Count != 0)
                    {
                        result += operands.Dequeue() + " ";
                    }

                    while (operats.Count != 0)
                    {
                        result += operats.Pop() + " ";
                    }
                }
                else
                {
                    //push variable.
                    operands.Enqueue(tok);
                }

            }


            while (operands.Count != 0)
            {
                result += operands.Dequeue() + " ";
            }

            while (operats.Count != 0)
            {
                result += operats.Pop() + " ";
            }


            return result.Replace('\t', ' ').Replace('\n', ' ').Replace("  ", " ");
        }

        /// <summary>
        /// Parses function and returns seed function
        /// </summary>
        /// <param name="pos"></param>
        /// <param name="seed"></param>
        /// <returns></returns>
        public override ulong SeedFunction(ulong pos, ulong seed)
        {
            return ParseSeedFunction(function, pos, seed);
        }

        public static ulong ParseSeedFunction(string function, ulong pos, ulong seed)
        {
            ulong result = 0;
            Stack<ulong> nums = new Stack<ulong>();

            String[] tokens = ConvertToRPN(function).Split(' ');

            //loop through every token
            foreach (String token in tokens)
            {
                try {
                    if (token.Length == 0) continue;
                    switch (token)
                    {
                        case "+":
                            nums.Push(nums.Pop() + nums.Pop());
                            break;
                        case "-":
                            {
                                var top = nums.Pop();
                                var bottom = nums.Pop();
                                nums.Push(bottom - top);
                            }
                            break;
                        case "/":
                            {
                                var top = nums.Pop();
                                var bottom = nums.Pop();
                                if (top == 0) top = 1;
                                nums.Push(bottom / top);
                            }
                            break;
                        case "*":
                            {
                                var top = nums.Pop();
                                var bottom = nums.Pop();
                                nums.Push(bottom * top);
                            }
                            break;
                        case "%":
                            {
                                var top = nums.Pop();
                                var bottom = nums.Pop();
                                if (top == 0) top = 1;
                                nums.Push(bottom % top);
                            }
                            break;
                        case "^":
                            {
                                var top = nums.Pop();
                                var bottom = nums.Pop();
                                nums.Push((ulong)Math.Pow(bottom, top));
                            }

                            break;
                        case "pos":
                            nums.Push(pos);
                            break;
                        case "seed":
                            nums.Push(seed);
                            break;
                        case "|":
                            {
                                var top = nums.Pop();
                                var bottom = nums.Pop();
                                nums.Push(bottom | top);
                            }
                            break;
                        case "&":
                            {
                                var top = nums.Pop();
                                var bottom = nums.Pop();
                                nums.Push(bottom & top);
                            }
                            break;

                        case "":
                            break;
                        default:
                            nums.Push(UInt64.Parse(token));
                            break;

                    }
                } catch(Exception ex) {
                    //divided by zero error 
                    nums.Push(1);
                }

            }

            //added this to add everything on the stack.
            while (nums.Count > 1)
            {
                nums.Push(nums.Pop() + nums.Pop());
            }

            if(nums.Count == 1) //just in case.
            result = nums.Pop();
            
            return result;
        }
    }
}
