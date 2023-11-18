PRE_SEQ_LEN=128
LR=1e-3

python /media/hnu/hnu2023/huangzhan/ChatGLM2-6B/ptuning/main.py \
    --do_train \
    --train_file /media/hnu/hnu2023/huangzhan/training/glm2/output7/data/data.json \
    --validation_file /media/hnu/hnu2023/huangzhan/training/glm2/output7/data/val.json \
    --preprocessing_num_workers 10 \
    --prompt_column content \
    --response_column summary \
    --overwrite_cache \
    --model_name_or_path /media/hnu/hnu2023/huangzhan/chatglm2-6b \
    --output_dir /media/hnu/hnu2023/huangzhan/training/glm2/output7 \
    --overwrite_output_dir \
    --max_source_length 128 \
    --max_target_length 256 \
    --gradient_accumulation_steps 16 \
    --per_device_train_batch_size 1 \
    --per_device_eval_batch_size 1 \
    --predict_with_generate \
    --max_steps 1500 \
    --logging_steps 10 \
    --save_steps 300 \
    --learning_rate $LR \
    --pre_seq_len $PRE_SEQ_LEN \
    --fp16

