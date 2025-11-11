import argparse
import os
import pandas as pd


def sample_csv(input_path: str, output_path: str, n_rows: int):
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")
    df = pd.read_csv(input_path)
    if n_rows >= len(df):
        # If requested size >= available, copy full file
        df_sample = df
    else:
        df_sample = df.sample(n=n_rows, random_state=42)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df_sample.to_csv(output_path, index=False)
    print(f"Saved {len(df_sample)} rows to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Create small dummy subsets of UNSW-NB15 train/test data")
    parser.add_argument("--train-input", default="data/UNSW_NB15_training-set.csv", help="Path to full training CSV")
    parser.add_argument("--test-input", default="data/UNSW_NB15_testing-set.csv", help="Path to full test CSV")
    parser.add_argument("--train-size", type=int, default=5000, help="Rows to sample for dummy train")
    parser.add_argument("--test-size", type=int, default=2000, help="Rows to sample for dummy test")
    parser.add_argument("--train-output", default="data/dummy_train.csv", help="Output path for dummy train")
    parser.add_argument("--test-output", default="data/dummy_test.csv", help="Output path for dummy test")
    args = parser.parse_args()

    sample_csv(args.train_input, args.train_output, args.train_size)
    sample_csv(args.test_input, args.test_output, args.test_size)
    print("Dummy dataset creation complete.")


if __name__ == "__main__":
    main()