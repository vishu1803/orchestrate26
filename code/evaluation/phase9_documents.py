"""Explicit opt-in runner for the unpromoted document experiment, not inference."""
import argparse
from functools import partial
import json
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ghost_audit.documents import validated_ocr_observations


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('evaluate','generate'))
    args,remainder=parser.parse_known_args()
    extractor=partial(validated_ocr_observations,enable_support_context=True)
    with patch('ghost_audit.pipeline.validated_ocr_observations',extractor):
        if args.mode=='evaluate':
            from evaluation.main import main as evaluate
            sys.argv=[sys.argv[0],*remainder]
            evaluate()
        else:
            generate_parser=argparse.ArgumentParser()
            generate_parser.add_argument('--dataset-dir')
            generate_parser.add_argument('--output',type=Path,required=True)
            generate_parser.add_argument('--report',type=Path,required=True)
            options=generate_parser.parse_args(remainder)
            from ghost_audit.submission import generate
            result=generate(options.dataset_dir,options.output,options.report)
            print(json.dumps({k:result[k] for k in ('rows','status_counts','output_sha256','elapsed_seconds')},sort_keys=True))


if __name__=='__main__':
    main()
