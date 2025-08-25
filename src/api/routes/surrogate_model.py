from fastapi import APIRouter
from fastapi import FastAPI, UploadFile, File
from fastapi import APIRouter, Form, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from io import BytesIO

import json
import pandas as pd
from typing import List, Dict

from run_model import run_predictions  # will not trigger Typer CLI

router = APIRouter()

@router.post("/run-model")
async def run_model_endpoint(
    config_file: str = Form(...),
    files: List[UploadFile] = File(...)
):
    """
    This endpoint accepts a configuration file name and multiple Excel files,
    runs the ML model, and returns the predictions in JSON format.
    """
    # ... (file reading logic is the same) ...
    dfs: Dict[str, pd.DataFrame] = {}

    for file in files:
        contents = await file.read()
        input_stream = BytesIO(contents)
        try:
            dfs[file.filename] = pd.read_excel(input_stream)
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": f"Error reading {file.filename}: {e}"})

    # Call the ML logic. 'results' is a dictionary of JSON strings.
    results = run_predictions(config_file=config_file, api_mode=True, building_data_dict=dfs)

    if not results or "error" in results:
        return JSONResponse(status_code=500, content=results)
        
    # The results are valid JSON strings, so we parse them back into
    # Python objects for a clean API response.
    json_results = {k: json.loads(v) for k, v in results.items()}

    # Pass the parsed Python objects to the response.
    return JSONResponse(status_code=200, content=json_results)
