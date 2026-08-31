import hashlib
import random
import string
import time
def generate_random_strings(num_strings):
  dataset = []
  chars = string.ascii_letters + string.digits + string.punctuation
  for _ in range(num_strings):
    length = random.randint(10, 30)
    random_str = "".join(random.choice(chars) for _ in range(length))
    dataset.append(random_str)
  return dataset
def analyze_hashing_performance(dataset):
  algorithms = {
      "MD5": hashlib.md5,
      "SHA-1": hashlib.sha1,
      "SHA-256": hashlib.sha256,
  }
  results = {}
  for name, algo_func in algorithms.items():
    seen_hashes = {}
    collisions = 0
    start_time = time.perf_counter()
    for text in dataset:
      hash_obj = algo_func(text.encode("utf-8"))
      hash_hex = hash_obj.hexdigest()
      if hash_hex in seen_hashes:
        collisions += 1
      else:
        seen_hashes[hash_hex] = text
    end_time = time.perf_counter()
    total_time = end_time - start_time
    results[name] = {"time": total_time, "collisions": collisions}
  return results
if __name__ == "__main__":
  dataset_size = random.randint(50, 100)
  print(f"[*] Generated dataset size: {dataset_size} random strings.\n")
  dataset = generate_random_strings(dataset_size)
  performance_data = analyze_hashing_performance(dataset)
  print(f"{'Algorithm':<10} | {'Time Taken (s)':<18} | {'Collisions':<10}")
  print("-" * 44)
  for algo, data in performance_data.items():
    print(f"{algo:<10} | {data['time']:<18.6f} | {data['collisions']:<10}")
  print("-" * 44)