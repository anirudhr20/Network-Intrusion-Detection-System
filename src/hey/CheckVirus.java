package hey;
import java.io.*;
import java.util.*;

class CheckVirus
{
String virus="";
String filename="";
String database[][] ={{"Trojan","Sign1"},{"Worm32","Sign2"}}; //Storing the virus names along with their file names
boolean found;
PrintStream ps; 
Scanner sc=new Scanner(System.in);
static int fcount;

CheckVirus() 
{
	try{
		ps=new PrintStream("log.txt");//Assigning the file name in which logging has to be done
	}catch(Exception e)
	{
		e.printStackTrace();
		
	}
}

public void read()
{
	System.out.println("Enter the filename");
	filename=sc.next();
}


public void compute()
{
	for(int i=0;i<database.length;i++)
	{
		if(filename.contains(database[i][1]))
		{
			virus=database[i][0];
			found=true;
			break;
		}
	}
}

public void addToLog()
{
	if(found)
	{
		try
		{
			Date d=new Date();
			
			ps.append(virus+" virus found in file "+filename+"on "+d);
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
}

/*public void display()
{
	if(found)
		System.out.println("\nFile is infected with "+virus+" virus");
	else
		System.out.println("File is virus free");
}
*/


}