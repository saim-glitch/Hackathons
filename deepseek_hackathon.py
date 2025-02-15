import os
import json
import ast
import requests
import subprocess
import streamlit as st
from tempfile import NamedTemporaryFile
from fpdf import FPDF
from docx import Document
from openai import OpenAI

# AIML API Configuration
base_url = "https://api.aimlapi.com/v1"
api_key = "9dc265c2a5204831b7fd062d4b20b5f0"  # Replace with your actual AIML API key
system_prompt = "You are a code reviewer. Analyze the code for vulnerabilities, efficiency, and best practices."
api = OpenAI(api_key=api_key, base_url=base_url)

# Function to analyze code using AIML API
def analyze_with_aiml(code: str):
    user_prompt = f"Analyze the following Python code for vulnerabilities, efficiency, and best practices:\n\n{code}"
    try:
        completion = api.chat.completions.create(
            model="deepseek/deepseek-r1",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.7,
            max_tokens=256,
        )
        return completion.choices[0].message.content
    except Exception as e:
        return {"error": f"AIML API request failed: {e}"}

# Function to perform static analysis using Bandit
def analyze_with_bandit(file_path: str):
    try:
        result = subprocess.run(["bandit", "-r", file_path, "-f", "json"], capture_output=True, text=True, check=True)
        return json.loads(result.stdout) if result.stdout else {}
    except subprocess.CalledProcessError as e:
        return {"error": f"Bandit analysis failed: {e}"}
    except FileNotFoundError:
        return {"error": "Bandit not found. Install it using `pip install bandit`"}

# Function to analyze code complexity using AST
def analyze_code_complexity(code: str):
    try:
        tree = ast.parse(code)
        functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        variables = [node.targets[0].id for node in ast.walk(tree) if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)]
        return {
            "total_functions": len(functions),
            "total_classes": len(classes),
            "total_variables": len(variables),
            "functions": functions,
            "classes": classes,
            "variables": variables,
            "complexity_score": len(functions) * 1.5
        }
    except Exception as e:
        return {"error": str(e)}

# Function to check dependencies for security vulnerabilities
def check_dependencies():
    try:
        result = subprocess.run(["pip-audit", "--format", "json"], capture_output=True, text=True, check=True)
        return json.loads(result.stdout) if result.stdout else {}
    except subprocess.CalledProcessError as e:
        return {"error": f"Dependency check failed: {e}"}
    except FileNotFoundError:
        return {"error": "pip-audit not found. Install it using `pip install pip-audit`"}

# Function to generate a structured report
def generate_report(file_path: str, aiml_results, bandit_results, complexity_results, dependencies_results):
    report = {
        "File Analyzed": os.path.basename(file_path),
        "AIML Analysis": aiml_results,
        "Security Analysis (Bandit)": bandit_results,
        "Code Complexity": complexity_results,
        "Dependency Analysis": dependencies_results,
        "Recommendations": generate_recommendations(aiml_results, bandit_results, complexity_results, dependencies_results)
    }
    return report

# Function to generate recommendations based on analysis
def generate_recommendations(aiml, bandit, complexity, dependencies):
    recommendations = []
    
    if "issues" in bandit and bandit["issues"]:
        recommendations.append("Your code has security vulnerabilities. Review Bandit's findings and apply recommended fixes.")
    if "complexity_score" in complexity and complexity["complexity_score"] > 5:
        recommendations.append("Your code is quite complex. Consider refactoring long functions into smaller, reusable ones.")
    if "error" in dependencies:
        recommendations.append("Dependency security check failed. Ensure `pip-audit` is installed and run manually.")
    
    return recommendations if recommendations else ["No critical issues detected. Your code looks good!"]

# PDF Report Generation
def generate_pdf_report(report, file_path):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt=f"Code Analysis Report: {os.path.basename(file_path)}", ln=True, align="C")
    
    pdf.ln(10)
    
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 10, f"File Analyzed: {os.path.basename(file_path)}")
    pdf.multi_cell(0, 10, f"AIML Analysis: {report['AIML Analysis']}")
    pdf.multi_cell(0, 10, f"Security Analysis (Bandit): {json.dumps(report['Security Analysis (Bandit)'], indent=4)}")
    pdf.multi_cell(0, 10, f"Code Complexity: {json.dumps(report['Code Complexity'], indent=4)}")
    pdf.multi_cell(0, 10, f"Dependency Analysis: {json.dumps(report['Dependency Analysis'], indent=4)}")
    pdf.multi_cell(0, 10, f"Recommendations: {', '.join(report['Recommendations'])}")
    
    pdf_output = f"{file_path}_report.pdf"
    pdf.output(pdf_output)
    return pdf_output

# Word Report Generation
def generate_word_report(report, file_path):
    doc = Document()
    doc.add_heading(f"Code Analysis Report: {os.path.basename(file_path)}", 0)
    
    doc.add_heading("File Analyzed", level=1)
    doc.add_paragraph(f"{os.path.basename(file_path)}")
    
    doc.add_heading("AIML Analysis", level=1)
    doc.add_paragraph(report['AIML Analysis'])
    
    doc.add_heading("Security Analysis (Bandit)", level=1)
    doc.add_paragraph(json.dumps(report['Security Analysis (Bandit)'], indent=4))
    
    doc.add_heading("Code Complexity", level=1)
    doc.add_paragraph(json.dumps(report['Code Complexity'], indent=4))
    
    doc.add_heading("Dependency Analysis", level=1)
    doc.add_paragraph(json.dumps(report['Dependency Analysis'], indent=4))
    
    doc.add_heading("Recommendations", level=1)
    doc.add_paragraph(f"{', '.join(report['Recommendations'])}")
    
    word_output = f"{file_path}_report.docx"
    doc.save(word_output)
    return word_output

# Streamlit UI
def main():
    st.title("🚀 AI-Powered Code Review & Vulnerability Detector")
    st.markdown("Upload your Python file to analyze for vulnerabilities, efficiency, and best practices.")

    uploaded_file = st.file_uploader("📂 Upload a Python file", type=["py"])
    if uploaded_file:
        with NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
            temp_file.write(uploaded_file.read())
            temp_file_path = temp_file.name
        
        with open(temp_file_path, "r") as f:
            code = f.read()
        
        st.subheader("Uploaded Code:")
        st.code(code, language="python")
        
        with st.spinner("Analyzing code... Please wait."):
            aiml_results = analyze_with_aiml(code)
            bandit_results = analyze_with_bandit(temp_file_path)
            complexity_results = analyze_code_complexity(code)
            dependencies_results = check_dependencies()
        
        report = generate_report(temp_file_path, aiml_results, bandit_results, complexity_results, dependencies_results)
        
        st.subheader("Analysis Results")
        st.json(report)
        
        st.subheader("Extracted Code Elements")
        st.write(f"**Functions:** {', '.join(report['Code Complexity']['functions'])}")
        st.write(f"**Classes:** {', '.join(report['Code Complexity']['classes'])}")
        st.write(f"**Variables:** {', '.join(report['Code Complexity']['variables'])}")
        
        st.subheader("Recommendations")
        for rec in report["Recommendations"]:
            st.write(f"- {rec}")
        
        # Download buttons for PDF and Word report
        pdf_file = generate_pdf_report(report, temp_file_path)
        word_file = generate_word_report(report, temp_file_path)
        
        st.download_button("Download PDF Report", open(pdf_file, "rb").read(), file_name=f"{os.path.basename(temp_file_path)}_report.pdf", mime="application/pdf")
        st.download_button("Download Word Report", open(word_file, "rb").read(), file_name=f"{os.path.basename(temp_file_path)}_report.docx", mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        
        # Clean up temporary files
        os.remove(temp_file_path)
        os.remove(pdf_file)
        os.remove(word_file)

if __name__ == "__main__":
    main()